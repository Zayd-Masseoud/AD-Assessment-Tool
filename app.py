# --- START OF FILE app.py ---

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, Response
from datetime import datetime, UTC # Use UTC from datetime
import threading
import os
import logging
import traceback
import csv
import io
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import joinedload
from weasyprint import HTML
from encryption import CIPHER  # Import CIPHER from encryption.py
# Correct relative import if models is in the same directory
from models import db, TargetConfig, AssessmentRun, Finding, ADUser, ADGroup, ADComputer, ADGroupMembership, PasswordPolicy
# Correct relative import if enumeration is in the same directory
from enumeration import ADEnumerator

# Define logger at module level if needed outside create_app, but generally better inside
# logging.basicConfig(...) can also be called here if run standalone

def create_app(test_config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__, static_folder='static')
    # Use a more robust way to generate/load secret key for production
    app.secret_key = os.environ.get('SECRET_KEY', b'_5#y2L"F4Q8z\n\xec]/') # Keep original default for now
    app.logger.info("Flask app created.") # Use app logger

    # Configure database URI - ensure path is correct for your OS
    # Consider using instance folder: 'sqlite:///' + os.path.join(app.instance_path, 'ad_assessment.db')
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'instance', 'ad_assessment.db'))
    db_uri = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
    app.logger.info(f"Using database URI: {db_uri}")

    app.config.from_mapping(
        SECRET_KEY=app.secret_key, # Use the one set above
        SQLALCHEMY_DATABASE_URI=db_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config:
        app.config.update(test_config)

    # Ensure the instance folder exists
    try:
        instance_dir = os.path.dirname(db_path)
        os.makedirs(instance_dir, exist_ok=True)
        app.logger.info(f"Instance folder ensured at: {instance_dir}")
    except OSError as e:
        app.logger.error(f"Could not create instance folder {instance_dir}: {e}")
        pass # Continue if it exists

    # Initialize extensions within the app factory
    db.init_app(app)
    migrate = Migrate(app, db) # Pass db instance

    # Configure logging within the app factory
    # Avoid basicConfig if Flask's default logger is sufficient or configure Flask's logger
    # If using basicConfig, ensure it's not called multiple times if app factory is reused
    # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
    # Or configure Flask's logger:
    app.logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(threadName)s - %(message)s')
    handler.setFormatter(formatter)
    if not app.logger.handlers: # Avoid adding multiple handlers on reload
        app.logger.addHandler(handler)


    # --- Define worker functions INSIDE create_app or ensure they have app_context ---
    # Option 1: Define inside create_app (simpler for direct app/db access)
    # Option 2: Define outside, pass 'app' instance if needed, use with app.app_context():

    # Using Option 1 for simplicity here:

    def run_enumeration_task_worker(app_instance, run_id): # Pass app instance
        """Worker function running inside a thread with app context."""
        thread_name = threading.current_thread().name
        # Must use app_instance passed to the thread
        with app_instance.app_context():
            # Use Session.get (SQLAlchemy 2.0 preferred)
            assessment_run = db.session.get(AssessmentRun, run_id)
            if not assessment_run:
                app_instance.logger.error(f"[{thread_name}] Could not find AssessmentRun with ID {run_id}")
                return

            target = assessment_run.target
            app_instance.logger.info(f"[{thread_name}] Starting enumeration for target: {target.domain_name} (Run ID: {run_id})")

            assessment_run.status = 'Running'
            assessment_run.progress_task = 'Initializing enumeration'
            assessment_run.progress_percentage = 5
            try:
                db.session.commit()
            except Exception as commit_err:
                 app_instance.logger.error(f"[{thread_name}] DB Commit Error (initial status): {commit_err}")
                 # Decide how to handle - maybe set status to error immediately?
                 return

            enumerator = None
            try:
                password = target.decrypt_password() if target.encrypted_password else None
                selected_modules_list = assessment_run.get_selected_modules()
                # --- Get subnets from the target object ---
                subnets_to_scan = target.subnets # Use the property that returns a list
                app_instance.logger.info(f"[{thread_name}] Passing selected modules: {selected_modules_list} and subnets: {subnets_to_scan} to ADEnumerator")
                # Assuming ADEnumerator does NOT need selected_modules in __init__
                # If it does, you need to add it back and modify ADEnumerator class
                enumerator = ADEnumerator(
                    target.domain_name,
                    target.dc_ip,
                    target.username,
                    password,
                    selected_modules=selected_modules_list, # Pass if needed by Enumerator
                    target_subnets=subnets_to_scan # Pass the subnets
                )
                # --- Call the ADEnumerator's main run method ---
                # This simplifies the loop below, assuming run_enumeration handles steps internally
                # If you want step-by-step progress, keep the loop structure
                app_instance.logger.info(f"[{thread_name}] Calling enumerator.run_enumeration()")
                results = enumerator.run_enumeration() # ADEnumerator should manage its steps
                app_instance.logger.info(f"[{thread_name}] Enumerator finished. Status: {results.get('status')}")

                # --- Update progress based on enumerator status ---
                # (This replaces the step-by-step loop if using run_enumeration directly)
                # You might need intermediate progress updates from within run_enumeration if needed
                # For now, just update based on final status

                if results.get("status") == "success":
                    assessment_run.progress_task = 'Processing results'
                    assessment_run.progress_percentage = 95
                    db.session.commit()

                    process_enumeration_results(app_instance, assessment_run.id, results) # Pass app_instance

                    assessment_run.status = 'Completed'
                    assessment_run.progress_task = 'Enumeration finished successfully'
                    assessment_run.progress_percentage = 100
                    assessment_run.end_time = datetime.now(UTC)
                    db.session.commit()
                    app_instance.logger.info(f"[{thread_name}] Enumeration task finished SUCCESSFULLY.")

                else: # Enumerator returned an error status
                    error_msg = results.get('error', 'Enumeration failed with unspecified error.')
                    app_instance.logger.error(f"[{thread_name}] Enumeration failed: {error_msg}")
                    assessment_run.status = 'Error'
                    assessment_run.progress_task = error_msg # Show the actual error
                    assessment_run.error_message = error_msg
                    assessment_run.progress_percentage = 100 # Indicate completion (with error)
                    assessment_run.end_time = datetime.now(UTC)
                    db.session.commit()
                    # Optionally process partial results if available and desired
                    # if results: process_enumeration_results(app_instance, assessment_run.id, results)
                    app_instance.logger.error(f"[{thread_name}] Enumeration task finished with ERROR.")


            except Exception as e:
                error_details = traceback.format_exc()
                app_instance.logger.error(f"[{thread_name}] Unexpected error in enumeration task: {str(e)}\n{error_details}")

                # Update assessment run status even on unexpected errors
                try:
                    assessment_run = db.session.get(AssessmentRun, run_id) # Re-fetch in case session expired
                    if assessment_run:
                        assessment_run.status = 'Error'
                        error_msg = f'Unexpected error during enumeration: {str(e)}'
                        assessment_run.progress_task = error_msg
                        assessment_run.error_message = error_msg
                        assessment_run.progress_percentage = 100 # Indicate completion (with error)
                        assessment_run.end_time = datetime.now(UTC)
                        db.session.commit()
                    else:
                         app_instance.logger.error(f"[{thread_name}] Could not find AssessmentRun {run_id} to update after unexpected error.")
                except Exception as final_commit_err:
                     app_instance.logger.error(f"[{thread_name}] DB Commit Error (unexpected exception handling): {final_commit_err}")

                app_instance.logger.error(f"[{thread_name}] Enumeration task finished with UNEXPECTED ERROR.")


    def process_enumeration_results(app_instance, run_id, results):
        """Process and save enumeration results to database"""
        assessment_run = db.session.get(AssessmentRun, run_id)
        if not assessment_run:
            app_instance.logger.error(f"Could not find AssessmentRun with ID {run_id} in process_results")
            return
        app_instance.logger.info(f"Processing results for Run ID: {run_id}")

        if 'findings' not in results:
            app_instance.logger.warning(f"No 'findings' key in results for Run ID: {run_id}. Skipping result processing.")
            try: db.session.commit()
            except Exception: db.session.rollback()
            return

        findings_data = results['findings']

        # Process users
        users_list = findings_data.get('users', [])
        app_instance.logger.info(f"Processing {len(users_list)} users.")
        for user_data in users_list:
            if not user_data.get('samAccountName'):
                app_instance.logger.warning(f"Skipping user data with missing samAccountName: {user_data.get('distinguishedName')}")
                continue
            ad_user = ADUser(
                run_id=run_id,
                username=user_data.get('samAccountName', ''),
                display_name=user_data.get('displayName'),
                sam_account_name=user_data.get('samAccountName'),
                user_principal_name=user_data.get('userPrincipalName'),
                distinguished_name=user_data.get('distinguishedName'),
                object_sid=user_data.get('objectSid'),
                pwd_last_set=datetime.fromisoformat(user_data['pwdLastSet']) if user_data.get('pwdLastSet') else None,
                password_age_days=user_data.get('passwordAgeDays'),
                password_expired=user_data.get('passwordExpired'),
                last_logon_timestamp=datetime.fromisoformat(user_data['lastLogonTimestamp']) if user_data.get('lastLogonTimestamp') else None,
                account_status=user_data.get('accountStatus')
            )
            db.session.add(ad_user)
        assessment_run.users_count = len(users_list)
        db.session.flush()

        # Process computers (unchanged, included for context)
        computers_list = findings_data.get('computers', [])
        app_instance.logger.info(f"Processing {len(computers_list)} computers.")
        for computer_data in computers_list:
            if not computer_data.get('samAccountName'):
                app_instance.logger.warning(f"Skipping computer data with missing samAccountName: {computer_data.get('distinguishedName')}")
                continue
            ad_computer = ADComputer(
                run_id=run_id,
                name=computer_data.get('samAccountName', '').rstrip('$'),
                dns_hostname=computer_data.get('dnsHostName'),
                distinguished_name=computer_data.get('distinguishedName'),
                object_sid=computer_data.get('objectSid'),
                sam_account_name=computer_data.get('samAccountName'),
                operating_system=computer_data.get('operatingSystem'),
            )
            db.session.add(ad_computer)
        assessment_run.computers_count = len(computers_list)
        db.session.flush()

        # Process groups and memberships
        user_dn_map = {u.distinguished_name: u.id for u in ADUser.query.filter_by(run_id=run_id).all()}
        computer_dn_map = {c.distinguished_name: c.id for c in ADComputer.query.filter_by(run_id=run_id).all()}
        groups_list = findings_data.get('groups', [])
        app_instance.logger.info(f"Processing {len(groups_list)} groups.")
        group_id_map = {}
        for group_data in groups_list:
            if not group_data.get('samAccountName') and not group_data.get('distinguishedName'):
                app_instance.logger.warning(f"Skipping group data with missing samAccountName and DN.")
                continue
            group_name = group_data.get('samAccountName') or group_data.get('distinguishedName').split(',')[0].replace('CN=','')
            ad_group = ADGroup(
                run_id=run_id,
                name=group_name,
                distinguished_name=group_data.get('distinguishedName'),
                object_sid=group_data.get('objectSid'),
                sam_account_name=group_data.get('samAccountName'),
                is_privileged=group_data.get('is_privileged', False)
            )
            db.session.add(ad_group)
            db.session.flush()
            group_id_map[ad_group.distinguished_name] = ad_group.id

        group_dn_map = {g.distinguished_name: g.id for g in ADGroup.query.filter_by(run_id=run_id).all()}
        app_instance.logger.info("Processing group memberships...")
        for group_data in groups_list:
            group_dn = group_data.get('distinguishedName')
            if not group_dn or group_dn not in group_dn_map:
                continue
            current_group_id = group_dn_map[group_dn]
            for member_dn in group_data.get('members', []):
                member_type = None
                member_id = None
                if member_dn in user_dn_map:
                    member_type = 'user'
                    member_id = user_dn_map[member_dn]
                elif member_dn in group_dn_map:
                    member_type = 'group'
                    member_id = group_dn_map[member_dn]
                elif member_dn in computer_dn_map:
                    member_type = 'computer'
                    member_id = computer_dn_map[member_dn]
                else:
                    app_instance.logger.debug(f"Member DN '{member_dn}' not found in users, groups, or computers for run {run_id}.")
                    continue
                if member_type and member_id:
                    membership = ADGroupMembership(
                        group_id=current_group_id,
                        member_type=member_type,
                        member_id=member_id,
                        depth=1
                    )
                    db.session.add(membership)
        assessment_run.groups_count = len(groups_list)
        db.session.flush()

        # Process password policy
        policy_data = findings_data.get('password_policy')
        if policy_data:
            app_instance.logger.info("Processing password policy.")
            strength_counts = policy_data.get('strength_counts', {'very_weak': 0, 'weak': 0, 'medium': 0, 'strong': 0, 'very_strong': 0})
            user_password_stats = policy_data.get('user_password_stats', [])
            policy = PasswordPolicy(
                run_id=run_id,
                min_length=policy_data.get('min_length'),
                password_history=policy_data.get('password_history'),
                max_age=policy_data.get('max_age'),
                min_age=policy_data.get('min_age'),
                lockout_threshold=policy_data.get('lockout_threshold'),
                complexity=policy_data.get('complexity'),
                issues=policy_data.get('issues'),
                strength_counts=strength_counts,
                user_password_stats=user_password_stats  # Assumes JSON serializable
            )
            db.session.add(policy)

        # Process NTDS hashes (unchanged)
        ntds_hashes_list = findings_data.get('ntds_hashes', [])
        if isinstance(ntds_hashes_list, list) and ntds_hashes_list:
            app_instance.logger.info(f"Storing {len(ntds_hashes_list)} extracted NTDS hashes for Run ID: {run_id}")
            assessment_run.ntds_results = ntds_hashes_list
        else:
            assessment_run.ntds_results = None

        # Process vulnerabilities
        vulnerabilities_list = results.get('vulnerabilities', [])
        app_instance.logger.info(f"Processing {len(vulnerabilities_list)} vulnerabilities/findings.")
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln_data in vulnerabilities_list:
            severity = vuln_data.get('severity', 'Info')
            finding = Finding(
                run_id=run_id,
                type=vuln_data.get('type', 'Vulnerability'),
                severity=severity,
                title=vuln_data.get('title', 'Unnamed Finding'),
                description=vuln_data.get('description'),
                impact=vuln_data.get('impact'),
                remediation=vuln_data.get('remediation'),
                affected_objects=vuln_data.get('affected_objects'),
                remediation_steps=vuln_data.get('remediation_steps'),
                references=vuln_data.get('references')
            )
            db.session.add(finding)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        assessment_run.critical_findings = severity_counts.get('Critical', 0)
        assessment_run.high_findings = severity_counts.get('High', 0)
        assessment_run.medium_findings = severity_counts.get('Medium', 0)
        assessment_run.low_findings = severity_counts.get('Low', 0)
        assessment_run.info_findings = severity_counts.get('Info', 0)

        try:
            db.session.commit()
            app_instance.logger.info(f"Successfully processed and committed results for Run ID: {run_id}")
        except Exception as commit_err:
            app_instance.logger.error(f"DB Commit Error during result processing for Run ID {run_id}: {commit_err}")
            db.session.rollback()

    # --- Routes ---
    @app.context_processor
    def inject_now():
        # Use timezone-aware datetime
        return {'now': datetime.now(UTC)}

    @app.context_processor
    def inject_template_scope():
        return dict(request=request)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/target_config', methods=['GET', 'POST'])
    def target_config():
        if request.method == 'POST':
            domain_name = request.form.get('domain_name', '').strip()
            dc_ip = request.form.get('dc_ip', '').strip()
            raw_subnets = request.form.get('target_subnets', '').strip()
            subnets_list = [subnet.strip() for subnet in raw_subnets.split(',') if subnet.strip()]

            # Query using filter_by and first()
            target = TargetConfig.query.filter_by(domain_name=domain_name).first()

            if not target:
                app.logger.info(f"Creating new target config for {domain_name}")
                target = TargetConfig(domain_name=domain_name, dc_ip=dc_ip)
                db.session.add(target)
            else:
                app.logger.info(f"Updating existing target config for {domain_name}")
                target.dc_ip = dc_ip

            target.set_target_subnets(subnets_list)

            if request.form.get('use_credentials') == 'on':
                username = request.form.get('username', '').strip()
                password = request.form.get('password', '') # Get password regardless of empty
                app.logger.info(f"Saving credentials for {domain_name}")
                target.username = username if username else None
                target.encrypt_password(password) # Handles empty password by setting None
            else:
                app.logger.info(f"Clearing credentials for {domain_name}")
                target.username = None
                target.encrypted_password = None # Explicitly set to None

            try:
                db.session.commit()
                app.logger.info(f"Target Config Saved: {target.domain_name}")
                flash('Target configuration saved successfully.', 'success')
            except Exception as e:
                 app.logger.error(f"Error saving target config: {e}")
                 db.session.rollback()
                 flash('Error saving target configuration. Please check logs.', 'danger')

            return redirect(url_for('attack_selection'))

        # GET Request
        targets = TargetConfig.query.all()
        # Provide a default empty config object if none exist for the template
        current_config = targets[0] if targets else TargetConfig()

        return render_template('target_config.html', current_config=current_config)

    @app.route('/attack_selection', methods=['GET', 'POST'])
    def attack_selection():
        # Use a more robust way to get the first target or handle none existing
        target = TargetConfig.query.order_by(TargetConfig.id).first()
        if not target:
            flash('Please configure the target environment first.', 'warning')
            return redirect(url_for('target_config'))

        if request.method == 'POST':
            selected_modules = request.form.getlist('modules')
            app.logger.info(f"Selected Modules: {selected_modules}")

            if not selected_modules:
                flash('Please select at least one assessment module.', 'warning')
                return redirect(url_for('attack_selection'))

            # Add warning only if attacks are selected without enumeration
            if 'enumeration' not in selected_modules and any(m != 'enumeration' for m in selected_modules):
                flash(
                    'Running attacks without prior enumeration might yield limited results. Consider running Basic Enumeration first.',
                    'warning')

            # Create the assessment run record
            assessment_run = AssessmentRun(
                target_id=target.id,
                status='Not Started',
                start_time=datetime.now(UTC) # Use timezone-aware UTC time
            )
            assessment_run.set_selected_modules(selected_modules) # Store selected modules
            db.session.add(assessment_run)
            try:
                db.session.commit()
                app.logger.info(f"Created AssessmentRun with ID: {assessment_run.id}")

                # Start the background thread ONLY if commit was successful
                # Pass the current app instance to the thread target
                enum_thread = threading.Thread(
                    target=run_enumeration_task_worker, # Use the worker function
                    args=(app, assessment_run.id,), # Pass app proxy and run_id
                    name=f"EnumThread-{assessment_run.id}",
                    daemon=True
                )
                enum_thread.start()
                app.logger.info(f"Started enumeration task thread for run ID: {assessment_run.id}")
                return redirect(url_for('attack_progress', run_id=assessment_run.id))

            except Exception as e:
                 app.logger.error(f"Error creating AssessmentRun or starting thread: {e}")
                 db.session.rollback()
                 flash('Error starting assessment run. Please check logs.', 'danger')
                 return redirect(url_for('attack_selection'))


        # GET Request
        available_modules = [
             {
                'name': 'Basic Enumeration & Vulnerability Scan',
                'value': 'enumeration',
                'desc': 'Discovers AD objects (Users, Groups, Computers), checks policy, trusts, and performs initial vulnerability checks (Kerberoastable, AS-REP Roasting, SMB Signing). Recommended first step.',
                'risk': 'Low',
                'risk_class': 'bg-info text-dark'
            },
            {
                'name': 'Kerberoasting Attack (Module)',
                'value': 'kerberoasting',
                'desc': '[Not Implemented] Attempt to extract TGS tickets for service accounts.',
                'risk': 'Medium',
                'risk_class': 'bg-warning text-dark'
            },
            {
                'name': 'AS-REP Roasting Attack (Module)',
                'value': 'asrep_roasting',
                'desc': '[Not Implemented] Attempt to get TGT data for users without pre-auth.',
                'risk': 'Medium',
                'risk_class': 'bg-warning text-dark'
            },
            {
                'name': 'Password Spray Attack (Module)',
                'value': 'password_spray',
                'desc': '[Not Implemented] Test common passwords against users. High risk!',
                'risk': 'High',
                'risk_class': 'bg-danger'
            },
           
             {
                'name': 'NTDS.dit Extraction (Module)',
                'value': 'ntds_extraction',
                'desc': '[Not Implemented] Attempt to extract the NTDS.dit database (requires high privileges).',
                'risk': 'Critical',
                'risk_class': 'bg-danger text-white' # Adjust class for visibility
             },
        ]

        # Check if *any* previous run completed successfully to enable attack modules
        successful_run = AssessmentRun.query.filter_by(status='Completed').order_by(AssessmentRun.start_time.desc()).first()
        enum_ran_successfully = successful_run is not None

        return render_template(
            'attack_selection.html',
            modules=available_modules,
            target_config=target,
            enum_ran_successfully=enum_ran_successfully
        )

    @app.route('/attack_progress')
    def attack_progress():
        run_id = request.args.get('run_id', type=int) # Get as integer
        assessment_run = None

        if run_id:
             assessment_run = db.session.get(AssessmentRun, run_id)
        else:
             # Get the most recent run if no ID specified
             assessment_run = AssessmentRun.query.order_by(AssessmentRun.start_time.desc()).first()

        if not assessment_run:
            flash('Assessment run not found or no runs available.', 'warning')
            # Redirect to selection if no specific run ID was given and none exist
            # Or show a specific 'no run' page
            return redirect(url_for('attack_selection' if not run_id else 'index'))

        # Fetch target associated with the run
        target = assessment_run.target # Access relationship

        return render_template(
            'attack_progress.html',
            run=assessment_run,
            target_config=target # Pass the target object
        )

    @app.route('/progress_status')
    def progress_status():
        # Consider getting run_id from request args if specific progress needed
        # run_id = request.args.get('run_id', type=int)
        # For now, just get the latest overall
        latest_run = AssessmentRun.query.order_by(AssessmentRun.start_time.desc()).first()

        response = {
            'percentage': 0,
            'status': 'Not Started',
            'current_task': 'No assessment run available',
            'completed': False,
            'error': None,
            'run_id': None # Add run_id to response
        }

        if latest_run:
            response.update({
                'percentage': latest_run.progress_percentage,
                'status': latest_run.status,
                'current_task': latest_run.progress_task or 'Waiting...',
                'completed': latest_run.status in ['Completed', 'Error'], # Completed or Error state means done
                'error': latest_run.error_message,
                'run_id': latest_run.id
            })

        return jsonify(response)


    # --- Severity Class Helpers ---
    def _get_severity_class(severity):
        # Simplified severity mapping
        mapping = {
            'critical': 'bg-danger text-white', # Ensure text visibility
            'high': 'bg-warning text-dark',
            'medium': 'bg-primary text-white',
            'low': 'bg-success text-white',
            'info': 'bg-info text-dark',
        }
        return mapping.get(str(severity).lower(), 'bg-secondary text-white') # Default

    def _get_severity_class_light(severity):
         mapping = {
            'critical': 'bg-danger-subtle text-emphasis-danger',
            'high': 'bg-warning-subtle text-emphasis-warning',
            'medium': 'bg-primary-subtle text-emphasis-primary',
            'low': 'bg-success-subtle text-emphasis-success',
            'info': 'bg-info-subtle text-emphasis-info',
        }
         return mapping.get(str(severity).lower(), 'bg-secondary-subtle text-emphasis-secondary')

    # --- Results Route (Single Definition) ---
    @app.route('/results')
    def results():
        app.logger.info("-" * 30)
        app.logger.info("Accessing /results route.")
        run_id = request.args.get('run_id', type=int)

        if run_id:
            assessment_run = db.session.get(AssessmentRun, run_id)
            if not assessment_run:
                flash(f'Assessment run with ID {run_id} not found.', 'warning')
                return redirect(url_for('results'))
        else:
            assessment_run = AssessmentRun.query.filter(
                AssessmentRun.status.in_(['Completed', 'Error'])
            ).order_by(AssessmentRun.start_time.desc()).first()
            if not assessment_run:
                running_run = AssessmentRun.query.filter_by(status='Running').order_by(AssessmentRun.start_time.desc()).first()
                if running_run:
                    flash('An assessment is currently running. Redirecting to progress page.', 'info')
                    return redirect(url_for('attack_progress', run_id=running_run.id))
                else:
                    flash('No assessment results available. Please configure a target and run an assessment.', 'info')
                    return render_template('results.html', run=None, total_findings=0)

        target_config = assessment_run.target
        vulnerabilities = []
        misconfigurations = []
        privileged_groups = []
        privileged_users = []
        password_policy_data = None
        recommendations = []
        ntds_hashes = []
        highest_severity = None
        critical_count = assessment_run.critical_findings or 0
        high_count = assessment_run.high_findings or 0
        medium_count = assessment_run.medium_findings or 0
        low_count = assessment_run.low_findings or 0
        info_count = assessment_run.info_findings or 0
        users_count = assessment_run.users_count or 'N/A'
        groups_count = assessment_run.groups_count or 'N/A'
        computers_count = assessment_run.computers_count or 'N/A'

        app.logger.info(f"Processing results for Run ID: {assessment_run.id}, Status: {assessment_run.status}")

        if assessment_run.status == 'Completed':
            app.logger.info("Processing SUCCESSFUL assessment results for display.")
            findings = Finding.query.filter_by(run_id=assessment_run.id).options(
                joinedload(Finding.affected_users),
                joinedload(Finding.affected_groups),
                joinedload(Finding.affected_computers)
            ).all()

            for finding in findings:
                severity = finding.severity or 'Info'
                affected_obj_list = []
                if finding.affected_users: affected_obj_list.extend([u.username for u in finding.affected_users])
                if finding.affected_groups: affected_obj_list.extend([g.name for g in finding.affected_groups])
                if finding.affected_computers: affected_obj_list.extend([c.name for c in finding.affected_computers])
                if not affected_obj_list and isinstance(finding.affected_objects, list):
                    affected_obj_list = finding.affected_objects

                finding_obj = {
                    'id': finding.id,
                    'severity': severity,
                    'severity_class': _get_severity_class(severity),
                    'severity_class_light': _get_severity_class_light(severity),
                    'title': finding.title or 'Unnamed Finding',
                    'description': finding.description or 'No description.',
                    'impact': finding.impact or 'Not specified.',
                    'affected_objects': affected_obj_list,
                    'remediation': finding.remediation or 'Not specified.',
                    'remediation_steps': finding.remediation_steps or [],
                    'references': finding.references or []
                }
                if finding.type == 'Misconfiguration':
                    misconfigurations.append(finding_obj)
                else:
                    vulnerabilities.append(finding_obj)

            # Process Privileged Groups
            privileged_groups_query = ADGroup.query.filter_by(run_id=assessment_run.id, is_privileged=True).options(
                joinedload(ADGroup.memberships).joinedload(ADGroupMembership.group)
            ).all()

            for group in privileged_groups_query:
                members = []
                memberships = ADGroupMembership.query.filter_by(group_id=group.id).all()
                member_user_ids = [m.member_id for m in memberships if m.member_type == 'user']
                member_group_ids = [m.member_id for m in memberships if m.member_type == 'group']
                member_computer_ids = [m.member_id for m in memberships if m.member_type == 'computer']

                if member_user_ids:
                    users = ADUser.query.filter(ADUser.id.in_(member_user_ids)).all()
                    members.extend([{'member_name': u.username, 'member_type': 'user'} for u in users])
                if member_group_ids:
                    groups = ADGroup.query.filter(ADGroup.id.in_(member_group_ids)).all()
                    members.extend([{'member_name': g.name, 'member_type': 'group'} for g in groups])
                if member_computer_ids:
                    computers = ADComputer.query.filter(ADComputer.id.in_(member_computer_ids)).all()
                    members.extend([{'member_name': c.name, 'member_type': 'computer'} for c in computers])

                privileged_groups.append({
                    'id': group.id,
                    'name': group.name,
                    'members': members,
                    'member_count': len(members),
                    'risk_level': 'Critical',
                    'risk_class': _get_severity_class('Critical')
                })

            # Process Privileged Users
            privileged_user_ids = set()
            for group in privileged_groups_query:
                memberships = ADGroupMembership.query.filter_by(group_id=group.id, member_type='user').all()
                privileged_user_ids.update(m.member_id for m in memberships)

            if privileged_user_ids:
                privileged_users_query = ADUser.query.filter(ADUser.id.in_(privileged_user_ids)).all()
                for user in privileged_users_query:
                    groups = [g.name for g in ADGroup.query.join(ADGroupMembership).filter(
                        ADGroupMembership.member_type == 'user',
                        ADGroupMembership.member_id == user.id,
                        ADGroup.is_privileged == True
                    ).all()]
                    privileged_users.append({
                        'id': user.id,
                        'username': user.username,
                        'display_name': user.display_name,
                        'groups': groups,
                        'password_age_days': user.password_age_days,
                        'password_expired': user.password_expired,
                        'last_logon': user.last_logon_timestamp.strftime('%Y-%m-%d %H:%M:%S') if user.last_logon_timestamp else 'Never',
                        'account_status': user.account_status,
                        'risk_level': 'Critical' if user.account_status == 'Enabled' else 'Medium'
                    })

            # Process Password Policy
            policy = PasswordPolicy.query.filter_by(run_id=assessment_run.id).first()
            if policy:
                password_policy_data = {
                    'min_length': policy.min_length,
                    'password_history': policy.password_history,
                    'max_age': policy.max_age,
                    'min_age': policy.min_age,
                    'lockout_threshold': policy.lockout_threshold,
                    'complexity': policy.complexity,
                    'issues': policy.issues or [],
                    'strength_counts': policy.strength_counts if isinstance(policy.strength_counts, dict) else
                        {'very_weak': 0, 'weak': 0, 'medium': 0, 'strong': 0, 'very_strong': 0},
                    'user_password_stats': policy.user_password_stats or []
                }

            for finding in findings:
                severity = finding.severity or 'Info'
                if not highest_severity:
                    highest_severity = severity
                elif severity == 'Critical':
                    highest_severity = 'Critical'
                    break
                elif severity == 'High' and highest_severity != 'Critical':
                    highest_severity = 'High'
                elif severity == 'Medium' and highest_severity not in ('Critical', 'High'):
                    highest_severity = 'Medium'
                elif severity == 'Low' and highest_severity not in ('Critical', 'High', 'Medium'):
                    highest_severity = 'Low'

            if highest_severity in ('Critical', 'High'):
                recommendations.append({
                    'priority': highest_severity,
                    'priority_class': _get_severity_class(highest_severity),
                    'title': 'Remediate Critical/High Findings Immediately',
                    'description': 'Address all Critical and High severity findings to reduce organizational risk.',
                    'steps': [
                        'Review details for each finding in the Vulnerabilities tab.',
                        'Implement the remediation steps provided for each finding.',
                        'Verify the effectiveness of remediation through re-assessment.'
                    ],
                    'resources': []
                })

            for finding in findings:
                if finding.title == 'Kerberoastable Accounts':
                    recommendations.append({
                        'priority': 'High',
                        'priority_class': _get_severity_class('High'),
                        'title': 'Secure Kerberoastable Accounts',
                        'description': 'Accounts with SPNs are vulnerable to Kerberoasting attacks, which can lead to unauthorized access.',
                        'steps': [
                            'Use strong, complex passwords (>25 characters) for accounts with SPNs.',
                            'Implement regular password rotation (every 30-60 days).',
                            'Consider using Group Managed Service Accounts (gMSAs) for services.'
                        ],
                        'resources': [
                            {'title': 'MITRE ATT&CK T1558.003', 'url': 'https://attack.mitre.org/techniques/T1558/003/'},
                            {'title': 'ADSecurity on Kerberoasting', 'url': 'https://adsecurity.org/?p=2293'}
                        ]
                    })
                elif finding.title == 'AS-REP Roastable Accounts':
                    recommendations.append({
                        'priority': 'Medium',
                        'priority_class': _get_severity_class('Medium'),
                        'title': 'Secure AS-REP Roastable Accounts',
                        'description': 'Accounts with pre-authentication disabled are vulnerable to AS-REP roasting attacks.',
                        'steps': [
                            'Enable Kerberos pre-authentication for affected accounts.',
                            'Use Set-ADUser -DoesNotRequirePreAuth $false to fix.',
                            'Ensure strong passwords if pre-auth remains disabled.'
                        ],
                        'resources': [
                            {'title': 'MITRE ATT&CK T1558.004', 'url': 'https://attack.mitre.org/techniques/T1558/004/'},
                            {'title': 'Harmj0y on AS-REP Roasting', 'url': 'https://blog.harmj0y.net/redteaming/roasting-as-reps/'}
                        ]
                    })
                elif finding.title == 'SMB Signing Not Required':
                    recommendations.append({
                        'priority': 'Medium',
                        'priority_class': _get_severity_class('Medium'),
                        'title': 'Enable SMB Signing',
                        'description': 'Hosts not requiring SMB signing are vulnerable to man-in-the-middle attacks.',
                        'steps': [
                            'Open Group Policy Management Console (GPMC).',
                            'Edit or create a GPO for domain controllers and/or member servers.',
                            'Navigate to Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options.',
                            'Enable "Microsoft network client: Digitally sign communications (always)".',
                            'Enable "Microsoft network server: Digitally sign communications (always)".',
                            'Apply the GPO to appropriate OUs.',
                            'Run "gpupdate /force" on target systems or wait for GPO refresh.'
                        ],
                        'resources': [
                            {'title': 'Microsoft Docs: SMB Signing', 'url': 'https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing'},
                            {'title': 'MITRE ATT&CK T1557.001', 'url': 'https://attack.mitre.org/techniques/T1557/001/'}
                        ]
                    })

        elif assessment_run.status == 'Error':
            app.logger.error(f"Displaying results page after error: {assessment_run.error_message}")
            flash(f"Assessment failed: {assessment_run.error_message}", 'danger')
            vulnerabilities.append({
                'id': 'enum_fail', 'severity': 'Critical',
                'severity_class': _get_severity_class('Critical'),
                'severity_class_light': _get_severity_class_light('Critical'),
                'title': 'Assessment Process Failed',
                'description': assessment_run.error_message or 'An error occurred.',
                'impact': 'Could not assess security posture.', 'affected_objects': ['N/A'],
                'remediation': 'Verify config, credentials, connectivity, permissions. Check logs.',
                'remediation_steps': [], 'references': []
            })
            critical_count = 1

        total_findings = critical_count + high_count + medium_count + low_count + info_count
        risk_level = 'N/A'
        risk_level_class = 'bg-secondary text-white'
        if critical_count > 0: risk_level, risk_level_class = 'Critical', _get_severity_class('Critical')
        elif high_count > 0: risk_level, risk_level_class = 'High', _get_severity_class('High')
        elif medium_count > 0: risk_level, risk_level_class = 'Medium', _get_severity_class('Medium')
        elif low_count > 0: risk_level, risk_level_class = 'Low', _get_severity_class('Low')
        elif info_count > 0: risk_level, risk_level_class = 'Informational', _get_severity_class('Info')

        assessment_info = {
            'target_domain': target_config.domain_name if target_config else 'N/A',
            'assessment_date': assessment_run.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if assessment_run.start_time else 'N/A',
            'assessment_type': ', '.join(assessment_run.get_selected_modules()) if assessment_run.selected_modules else 'N/A',
            'duration': str(assessment_run.end_time - assessment_run.start_time).split('.')[0] if assessment_run.end_time else 'N/A',
            'total_tests': total_findings,
            'users_count': users_count,
            'groups_count': groups_count,
            'computers_count': computers_count,
        }

        app.logger.info(f"Rendering results.html for Run ID {assessment_run.id}. Risk: {risk_level}, Findings: {total_findings}")

        try:
            return render_template(
                'results.html',
                run=assessment_run,
                target_config=target_config,
                **assessment_info,
                risk_level=risk_level,
                risk_level_class=risk_level_class,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                info_count=info_count,
                total_findings=total_findings,
                vulnerabilities=vulnerabilities,
                misconfigurations=misconfigurations,
                privileged_groups=privileged_groups,
                privileged_users=privileged_users,  # New
                password_policy=password_policy_data,
                recommendations=recommendations,
                ntds_hashes=assessment_run.ntds_results if assessment_run.ntds_results else []
            )
        except Exception as render_err:
            app.logger.error(f"Error during render_template call in /results: {render_err}", exc_info=True)
            return render_template('error.html', error_message="An error occurred while rendering the results page."), 500

    @app.route('/export_csv')
    def export_csv():
        # Get latest completed/errored run for export
        assessment_run = AssessmentRun.query.filter(
            AssessmentRun.status.in_(['Completed', 'Error'])
        ).order_by(AssessmentRun.start_time.desc()).first()

        if not assessment_run:
            flash('No completed assessment results available for export.', 'warning')
            return Response('No assessment results available', status=404, mimetype='text/plain')

        output = io.StringIO()
        writer = csv.writer(output)
        # Define headers
        writer.writerow(['Finding ID', 'Type', 'Severity', 'Title', 'Description',
                         'Affected Objects', 'Impact', 'Remediation Summary',
                         'Remediation Steps', 'References'])

        findings = Finding.query.filter_by(run_id=assessment_run.id).all()
        for finding in findings:
            # Prepare data for CSV row
            affected_obj_list = []
            # Note: Accessing relationships here might be slow if not eager loaded.
            # Consider optimizing if export is slow.
            # Example - this requires loading relationships:
            # if finding.affected_users: affected_obj_list.extend([u.username for u in finding.affected_users])
            # ... etc for groups/computers ...
            # Fallback to JSON field:
            if isinstance(finding.affected_objects, list):
                affected_obj_list = finding.affected_objects

            # Format list fields for CSV (e.g., newline separated or semicolon)
            steps_str = "\n".join(finding.remediation_steps) if isinstance(finding.remediation_steps, list) else ""
            refs_str = "\n".join([f"{ref.get('title', '')}: {ref.get('url', '')}" for ref in finding.references]) if isinstance(finding.references, list) else ""

            writer.writerow([
                finding.id,
                finding.type or '',
                finding.severity or '',
                finding.title or '',
                finding.description or '',
                '; '.join(map(str, affected_obj_list)), # Join list with semicolon
                finding.impact or '',
                finding.remediation or '',
                steps_str,
                refs_str
            ])

        # Create timestamped filename
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"assessment_results_{assessment_run.id}_{timestamp}.csv"

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )

    @app.route('/export_pdf')
    def export_pdf():
        # Get latest completed/errored run for export
        assessment_run = AssessmentRun.query.filter(
            AssessmentRun.status.in_(['Completed', 'Error'])
        ).order_by(AssessmentRun.start_time.desc()).first()

        if not assessment_run:
            flash('No completed assessment results available for export.', 'warning')
            return Response('No assessment results available', status=404, mimetype='text/plain')

        # --- Gather data for PDF (Similar logic to /results route) ---
        # This part is largely duplicated from /results - consider refactoring into a helper function
        target_config = assessment_run.target
        vulnerabilities = []
        misconfigurations = []
        privileged_groups = []
        password_policy_data = None
        recommendations = []
        critical_count = assessment_run.critical_findings or 0
        high_count = assessment_run.high_findings or 0
        medium_count = assessment_run.medium_findings or 0
        low_count = assessment_run.low_findings or 0
        info_count = assessment_run.info_findings or 0
        users_count = assessment_run.users_count or 'N/A'
        groups_count = assessment_run.groups_count or 'N/A'
        computers_count = assessment_run.computers_count or 'N/A'

        # Populate findings, groups, policy, recommendations (reuse logic from /results)
        # ... (Copy the data gathering loops from the /results route here) ...
        # ... (Ensure all necessary data is fetched and processed) ...
        # --- Start copied/refactored data gathering ---
        findings = Finding.query.filter_by(run_id=assessment_run.id).options(
            joinedload(Finding.affected_users),
            joinedload(Finding.affected_groups),
            joinedload(Finding.affected_computers)
        ).all()
        # ... (rest of the finding processing loop from /results) ...
        for finding in findings:
                severity = finding.severity or 'Info' # Default severity
                affected_obj_list = []
                if finding.affected_users: affected_obj_list.extend([u.username for u in finding.affected_users])
                if finding.affected_groups: affected_obj_list.extend([g.name for g in finding.affected_groups])
                if finding.affected_computers: affected_obj_list.extend([c.name for c in finding.affected_computers])
                if not affected_obj_list and isinstance(finding.affected_objects, list):
                    affected_obj_list = finding.affected_objects

                finding_obj = {
                    'id': finding.id,
                    'severity': severity,
                    'severity_class': _get_severity_class(severity),
                    'severity_class_light': _get_severity_class_light(severity),
                    'title': finding.title or 'Unnamed Finding',
                    'description': finding.description or 'No description.',
                    'impact': finding.impact or 'Not specified.',
                    'affected_objects': affected_obj_list,
                    'remediation': finding.remediation or 'Not specified.',
                    'remediation_steps': finding.remediation_steps or [],
                    'references': finding.references or []
                }
                if finding.type == 'Misconfiguration': misconfigurations.append(finding_obj)
                else: vulnerabilities.append(finding_obj)

        # Privileged Groups (simplified for brevity - reuse /results logic)
        # ...

        # Password Policy (simplified - reuse /results logic)
        policy = PasswordPolicy.query.filter_by(run_id=assessment_run.id).first()
        if policy: password_policy_data = {k: getattr(policy, k) for k in policy.__table__.columns.keys()} # Basic copy

        # Recommendations (simplified - reuse /results logic)
        # ...
        # --- End copied/refactored data gathering ---


        total_findings = critical_count + high_count + medium_count + low_count + info_count
        risk_level = 'N/A'
        risk_level_class = 'bg-secondary text-white'
        if critical_count > 0: risk_level, risk_level_class = 'Critical', _get_severity_class('Critical')
        elif high_count > 0: risk_level, risk_level_class = 'High', _get_severity_class('High')
        # ... (rest of risk level calculation) ...

        assessment_info = {
             'target_domain': target_config.domain_name if target_config else 'N/A',
             'assessment_date': assessment_run.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if assessment_run.start_time else 'N/A',
             # ... (rest of assessment_info) ...
             'users_count': users_count,
             'groups_count': groups_count,
             'computers_count': computers_count,
             'total_tests': total_findings,
         }


        # --- Render HTML for PDF generation ---
        try:
            # Use the same results.html template
            html_content = render_template(
                'results.html', # Or a dedicated PDF template: 'pdf_report.html'
                run=assessment_run,
                target_config=target_config,
                 **assessment_info,
                risk_level=risk_level,
                risk_level_class=risk_level_class,
                critical_count=critical_count,
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count,
                info_count=info_count,
                total_findings=total_findings,
                vulnerabilities=vulnerabilities,
                misconfigurations=misconfigurations,
                privileged_groups=privileged_groups,
                password_policy=password_policy_data,
                recommendations=recommendations,
                # Add any other needed context
                is_pdf_export=True # Optional flag for template adjustments
            )

            app.logger.info(f"Generating PDF for Run ID: {assessment_run.id}")
            # Generate PDF using WeasyPrint
            pdf = HTML(string=html_content, base_url=request.url_root).write_pdf()
            app.logger.info(f"PDF generation successful for Run ID: {assessment_run.id}")

            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            filename = f"assessment_report_{assessment_run.id}_{timestamp}.pdf"

            return Response(
                pdf,
                mimetype='application/pdf',
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
        except Exception as e:
            app.logger.error(f"Error generating PDF for Run ID {assessment_run.id}: {str(e)}", exc_info=True)
            flash('Failed to generate PDF report. Please check server logs.', 'danger')
            # Redirect back to results page on PDF error
            return redirect(url_for('results', run_id=assessment_run.id))


    # Return the configured app instance
    return app


# --- Main execution block ---
if __name__ == '__main__':
    flask_app = create_app()
    # Consider environment variables for host/port/debug
    run_debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    run_host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    run_port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    flask_app.run(debug=run_debug, host=run_host, port=run_port)