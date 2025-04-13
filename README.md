# Microsoft 365 Security Baseline Checker

## Description
The **Microsoft 365 Security Baseline Checker** is a Python-based tool designed to perform a comprehensive security audit of your Microsoft 365 environment. It uses the Microsoft Graph API to validate configurations against Microsoft's security baseline recommendations. The tool provides detailed insights into security settings, such as MFA enforcement, admin account monitoring, conditional access policies, Microsoft Teams settings, data retention policies, and more.

> **Disclaimer**: This tool is intended for authorized audits of Microsoft 365 environments. Unauthorized use may violate laws and agreements.

---

## Features
- **MFA (Multi-Factor Authentication) Check**:
  - Verifies if MFA is enabled for all users.
- **Admin Accounts Audit**:
  - Lists all Global Administrator accounts and flags if there are too many.
- **Conditional Access Policies**:
  - Reviews and lists all active conditional access policies, including their conditions.
- **Inactive User Detection**:
  - Identifies users with no recent sign-in activity.
- **Secure Score Evaluation**:
  - Fetches the Microsoft Secure Score and provides actionable insights.
- **Microsoft Teams Settings**:
  - Audits Microsoft Teams configurations, such as visibility, archived status, and more.
- **Data Retention Policies**:
  - Evaluates existing data retention policies and their configurations.

---

## Requirements
- Python 3.8 or higher
- **Microsoft Graph API Permissions**:
  - `Directory.Read.All`
  - `Reports.Read.All`
  - `SecurityEvents.Read.All`
  - `Team.ReadBasic.All`
  - `Policy.Read.All`
- Install required dependencies:
  ```bash
  pip install requests
  ```

---

## Setup
1. **Register an App in Azure Active Directory**:
   - Go to the **Azure Portal** and navigate to **Azure Active Directory > App Registrations**.
   - Click **New Registration** and provide a name for the app.
   - Set the **Redirect URI** to `https://login.microsoftonline.com/common/oauth2/nativeclient`.
   - Copy the **Tenant ID** and **Client ID** once the app is created.
   - Create a **Client Secret** under **Certificates & Secrets** and securely copy it.

2. **Assign API Permissions**:
   - Go to **API Permissions** within the app's settings.
   - Add the following Microsoft Graph API permissions:
     - `Directory.Read.All`
     - `Reports.Read.All`
     - `SecurityEvents.Read.All`
     - `Team.ReadBasic.All`
     - `Policy.Read.All`
   - Grant **admin consent** for these permissions.

3. **Update the Script**:
   - Replace the placeholders in the script with your `Tenant ID`, `Client ID`, and `Client Secret`:
     ```python
     TENANT_ID = "your-tenant-id"
     CLIENT_ID = "your-client-id"
     CLIENT_SECRET = "your-client-secret"
     ```

---

## Usage
1. Clone this repository:
   ```bash
   git clone https://github.com/diegomessiah/microsoft-365-security-baseline.git
   cd microsoft-365-security-baseline
   ```

2. Run the script:
   ```bash
   python microsoft_365_security_baseline_complete.py
   ```

3. The script will generate a detailed audit report in the current directory with a filename like:
   ```
   microsoft_365_security_audit_YYYYMMDD_HHMMSS.txt
   ```

---

## Example Report
```plaintext
Microsoft 365 Security Audit Report - 2025-04-13 22:30:14
==================================================
Checking MFA Configuration:
- MFA is enabled for 85/100 users.
- Warning: Not all users have MFA enabled. Enforce MFA for better security.

Checking Admin Accounts:
- Found 5 Global Admin accounts: admin1@domain.com, admin2@domain.com, admin3@domain.com, admin4@domain.com, admin5@domain.com
- Warning: Too many Global Admin accounts. Reduce to 2-3 as per best practices.

Checking Conditional Access Policies:
- Found 3 active Conditional Access policies.
  - Policy Name: Require MFA for External Users
  - Policy Name: Block Legacy Authentication
  - Policy Name: Require Compliant Devices

Checking Microsoft Teams Settings:
- Found 10 Teams.
  - Team Name: IT Support
    - Visibility: Private
    - Is Archived: False
  - Team Name: Sales
    - Visibility: Public
    - Is Archived: False

Checking Data Retention Policies:
- Found 2 Retention Policies.
  - Policy Name: General Retention
    - Status: Enabled
    - Locations: {"Exchange": "All", "SharePoint": "All"}

Checking Secure Score:
- Secure Score: 65/100 (65.00%)
==================================================
```

---

## Customization
- **Add More Checks**: Extend the script to include additional security baseline checks based on your organization's requirements.
- **Automate Audits**: Schedule the script to run periodically using a task scheduler or CI/CD pipeline.

---

## Limitations
- The script requires administrative permissions to access the Microsoft Graph API.
- Ensure the app registration in Azure AD has the correct permissions for the script to function.

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Contributions
Contributions are welcome! Feel free to submit a pull request or open an issue to improve the tool or add new features.

---

## Author
**Diego Messiah**
- GitHub: [diegomessiah](https://github.com/diegomessiah)
