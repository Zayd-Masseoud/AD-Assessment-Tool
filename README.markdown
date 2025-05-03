# AD Assessment Tool

The AD Assessment Tool is a Flask-based web application designed to assess Active Directory (AD) environments for security vulnerabilities. It performs enumeration and vulnerability checks across three categories: **Account Vulnerabilities**, **Policy Vulnerabilities**, and **Protocol Vulnerabilities**. The tool provides a user-friendly interface to configure target AD environments, select assessment modules, monitor progress, and generate PDF reports of findings.

## Features
- **Target Configuration**: Configure AD domain, DC IP, subnets, and credentials.
- **Modular Assessments**: Select from Account, Policy, and Protocol vulnerability scans.
- **Real-Time Progress**: Monitor assessment progress via a web interface.
- **PDF Reports**: Generate detailed reports of vulnerabilities and findings.
- **Secure Credential Handling**: Encrypts passwords using the `cryptography` library.

## Prerequisites
- **Python**: Version 3.13 (other versions like 3.10–3.12 may work but are untested).
- **Operating System**: Windows (recommended for NTLM authentication); Linux/macOS may work with adjustments.
- **System Libraries for WeasyPrint**:
  - Windows: Install GTK3 and dependencies via MSYS2 (`pacman -S mingw-w64-x86_64-gtk3 mingw-w64-x86_64-cairo mingw-w64-x86_64-pango`).
  - Ubuntu: `sudo apt-get install python3-dev python3-pip python3-setuptools python3-wheel libcairo2-dev libpango1.0-dev`.
  - macOS: `brew install python cairo pango`.
- **Active Directory Access**: A reachable Domain Controller (DC) on port 389 (LDAP) or 636 (LDAPS), with valid credentials or anonymous bind enabled.

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Zayd-Masseoud/AD-Assessment-Tool
   cd AD-Assessment-Tool


2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # On Windows
   source venv/bin/activate  # On Linux/macOS
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   The `requirements.txt` includes:
   - Flask==3.0.3
   - Flask-SQLAlchemy==3.1.1
   - Flask-Migrate==4.0.7
   - SQLAlchemy==2.0.35
   - ldap3==2.9.1
   - weasyprint==63.0
   - cryptography==43.0.1
   - pycryptodome==3.19.0
   - Jinja2>=3.0.0

4. **Set Up the Database**:
   ```bash
   python app.py
   ```
   The application creates an SQLite database (`instance/ad_assessment.db`) on first run.

## Usage
1. **Run the Application**:
   ```bash
   python app.py
   ```
   The app runs on `http://127.0.0.1:5000` by default.

2. **Configure the Target**:
   - Navigate to `/target_config`.
   - Enter:
     - **Domain Name**: AD domain (e.g., `example.com`).
     - **DC IP**: Domain Controller IP address.
     - **Subnets**: CIDR notations (e.g., `192.168.1.0/24`).
     - **Username/Password**: AD credentials (e.g., `DOMAIN\username` or `username@domain.com`) or leave blank for anonymous bind.

3. **Select Assessment Modules**:
   - Go to `/attack_selection`.
   - Choose modules: Account Vulnerabilities, Policy Vulnerabilities, Protocol Vulnerabilities.
   - Click "Run Selected Assessment Modules".

4. **Monitor Progress**:
   - The `/attack_progress` page shows real-time progress.
   - Cancel the assessment if needed.

5. **View Results**:
   - After completion, view findings at `/results`.
   - Download a PDF report of vulnerabilities.

## Security Notes
- **Authorization**: Ensure you have permission to assess the target AD environment.
- **Credentials**: Passwords are encrypted in the database using `cryptography`.
- **Network**: Use LDAPS (port 636) if Simple Bind is enabled to avoid sending credentials in plain text.
- **Anonymous Bind**: Most AD environments disable anonymous binds; provide valid credentials for full functionality.

## Troubleshooting
- **MD4 Error**: If you see `unsupported hash type MD4`, ensure `pycryptodome` is installed. Alternatively, install `pyspnego` for Windows SSPI-based NTLM.
- **WeasyPrint Errors**: Verify system libraries (Cairo, Pango) are installed.
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
This project is licensed under the MIT License (or specify your preferred license).