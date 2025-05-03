# AD Assessment Tool

The AD Assessment Tool is a Flask-based web application designed to assess Active Directory (AD) environments for security vulnerabilities. It performs enumeration and vulnerability checks across three categories: **Account Vulnerabilities**, **Policy Vulnerabilities**, and **Protocol Vulnerabilities**. The tool provides a user-friendly interface to configure target AD environments, select assessment modules, monitor progress, and generate PDF reports of findings.

## Features
- **Target Configuration**: Configure AD domain, DC IP, subnets, and credentials.
- **Modular Assessments**: Select from Account, Policy, and Protocol vulnerability scans.
- **Real-Time Progress**: Monitor assessment progress via a web interface.
- **PDF Reports**: Generate detailed reports of vulnerabilities and findings.
- **Secure Credential Handling**: Encrypts passwords using the `cryptography` library.

## Prerequisites
- **Python**: Version 3.13 (recommended) or 3.12 (Kali Linux default). Other versions (3.10–3.12) may work but are untested.
- **Operating System**: Windows (recommended for NTLM authentication); Linux (including Kali) or macOS supported with adjustments.
- **System Libraries for WeasyPrint**:
  - **Kali Linux/Ubuntu**:
    ```bash
    sudo apt-get update
    sudo apt-get install -y python3-dev python3-pip python3-setuptools python3-wheel libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev
    ```
  - **Windows**: Install GTK3 and dependencies via MSYS2:
    ```bash
    pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-cairo mingw-w64-x86_64-pango
    ```
  - **macOS**:
    ```bash
    brew install python cairo pango
    ```
- **Active Directory Access**: A reachable Domain Controller (DC) on port 389 (LDAP) or 636 (LDAPS), with valid credentials or anonymous bind enabled.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Zayd-Masseoud/AD-Assessment-Tool.git
   cd AD-Assessment-Tool
   ```

2. **Set Up a Virtual Environment**:
   - **Kali Linux** (and other Linux distributions):
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
     Note: Kali Linux uses an externally managed Python environment (PEP 668). Always install dependencies in a virtual environment to avoid conflicts.
   - **Windows**:
     ```bash
     python -m venv venv
     .\venv\Scripts\activate
     ```
   - **macOS**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install System Dependencies** (Kali Linux):
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3-dev python3-pip python3-setuptools python3-wheel libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev
   ```

4. **Install Python Dependencies**:
   - With the virtual environment active, run:
     ```bash
     pip install -r requirements.txt
     ```
   - The `requirements.txt` includes:
     - Flask==3.0.3
     - Flask-SQLAlchemy==3.1.1
     - Flask-Migrate==4.0.7
     - SQLAlchemy==2.0.35
     - ldap3==2.9.1
     - weasyprint==63.0
     - cryptography==42.0.8
     - pycryptodome==3.19.0
     - Jinja2>=3.0.0
     - impacket==0.12.0
   - Note: `impacket` requires `pyOpenSSL==24.0.0`, which downgrades `cryptography` to `42.0.8` due to compatibility constraints.
   - If you encounter compatibility issues with Python 3.12 (Kali’s default), try downgrading `weasyprint`:
     ```text
     weasyprint==62.3
     ```

5. **Initialize the Database**:
   - Set up the SQLite database and apply migrations:
     ```bash
     ./venv/bin/flask db init
     ./venv/bin/flask db migrate -m "Initial migration"
     ./venv/bin/flask db upgrade
     ```
   - Alternatively, modify the PATH to prioritize the virtual environment’s `flask` command:
     ```bash
     export PATH="$PWD/venv/bin:$PATH"
     flask db init
     flask db migrate -m "Initial migration"
     flask db upgrade
     ```
   - This creates `instance/ad_assessment.db` with the necessary tables (e.g., `target_config`).
   - Note: If the `migrations/` directory already exists, skip `flask db init`.

6. **Run the Application**:
   ```bash
   python app.py
   ```
   The app runs on `http://127.0.0.1:5000` by default.

## Usage
1. **Configure the Target**:
   - Navigate to `/target_config`.
   - Enter:
     - **Domain Name**: AD domain (e.g., `example.com`).
     - **DC IP**: Domain Controller IP address.
     - **Subnets**: CIDR notations (e.g., `192.168.1.0/24`).
     - **Username/Password**: AD credentials (e.g., `DOMAIN\username` or `username@domain.com`) or leave blank for anonymous bind.

2. **Select Assessment Modules**:
   - Go to `/attack_selection`.
   - Choose modules: Account Vulnerabilities, Policy Vulnerabilities, Protocol Vulnerabilities.
   - Click "Run Selected Assessment Modules".

3. **Monitor Progress**:
   - The `/attack_progress` page shows real-time progress.
   - Cancel the assessment if needed.

4. **View Results**:
   - After completion, view findings at `/results`.
   - Download a PDF report of vulnerabilities.

## Security Notes
- **Authorization**: Ensure you have permission to assess the target AD environment.
- **Credentials**: Passwords are encrypted in the database using `cryptography`.
- **Network**: Use LDAPS (port 636) if Simple Bind is enabled to avoid sending credentials in plain text.
- **Anonymous Bind**: Most AD environments disable anonymous binds; provide valid credentials for full functionality.

## Troubleshooting
- **Missing Dependencies** (e.g., `ModuleNotFoundError: No module named 'flask_migrate'`):
  - Verify the virtual environment is active:
    ```bash
    source venv/bin/activate
    ```
  - Ensure all dependencies are installed:
    ```bash
    pip install -r requirements.txt
    ```
  - Check `Flask-Migrate`:
    ```bash
    pip show flask-migrate
    ```
  - If missing or corrupted, reinstall:
    ```bash
    pip uninstall flask-migrate
    pip install Flask-Migrate==4.0.7
    ```
  - If the error persists, recreate the virtual environment:
    ```bash
    deactivate
    rm -rf venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
- **Flask Command Uses System Python** (e.g., `which flask` shows `/usr/bin/flask`):
  - Use the virtual environment’s `flask` command:
    ```bash
    ./venv/bin/flask db init
    ./venv/bin/flask db migrate -m "Initial migration"
    ./venv/bin/flask db upgrade
    ```
  - Alternatively, modify the PATH:
    ```bash
    export PATH="$PWD/venv/bin:$PATH"
    ```
  - Verify the correct `flask` is used:
    ```bash
    which flask
    ```
    Expected output: `/home/zayd/test/AD-Assessment-Tool/venv/bin/flask`
- **Database Error** (`no such table: target_config`):
  - Ensure the database is initialized:
    ```bash
    ./venv/bin/flask db upgrade
    ```
  - If the error persists, delete the database and reapply migrations:
    ```bash
    rm instance/ad_assessment.db
    rm -rf migrations/
    ./venv/bin/flask db init
    ./venv/bin/flask db migrate -m "Initial migration"
    ./venv/bin/flask db upgrade
    ```
- **Externally Managed Environment (Kali Linux)**:
  - Error: `error: externally-managed-environment`
  - Solution: Use a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```
- **MD4 Error**: If you see `unsupported hash type MD4`, ensure `pycryptodome` is installed. Alternatively, install `pyspnego` for Windows SSPI-based NTLM.
- **WeasyPrint Errors**: Verify system libraries (Cairo, Pango) are installed:
  ```bash
  sudo apt-get install -y libcairo2-dev libpango1.0-dev libgdk-pixbuf2.0-dev
  ```
- **Impacket Errors**: Ensure `impacket` is installed for SMB/Kerberos checks:
  ```bash
  pip install impacket==0.12.0
  ```
- **LDAP Connection**: Test connectivity with:
  ```bash
  telnet <dc_ip> 389
  ldapsearch -H ldap://<dc_ip> -D "<username>@<domain>" -w "<password>" -b "DC=<domain>,DC=com" "(objectClass=user)" sAMAccountName
  ```
- **Logs**: Check console output for detailed errors.

## Contributing
- Fork the repository and create a pull request with your changes.
- Report issues or suggest features via GitHub Issues.

## License
This project is licensed under the MIT License.