import requests
import json
from datetime import datetime

# Constants
TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"
GRAPH_API_BASE_URL = "https://graph.microsoft.com/v1.0"

class Microsoft365SecurityAudit:
    def __init__(self):
        self.access_token = None
        self.report = []

    def get_access_token(self):
        """Get an access token from Microsoft Graph API."""
        url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.access_token = response.json().get("access_token")
        else:
            raise Exception(f"Failed to get access token: {response.text}")

    def make_graph_request(self, endpoint):
        """Make a request to the Microsoft Graph API."""
        url = f"{GRAPH_API_BASE_URL}/{endpoint}"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            self.report.append(f"Error accessing {endpoint}: {response.text}")
            return None

    def check_mfa(self):
        """Check MFA status for all users."""
        self.report.append("\nChecking MFA Configuration:")
        endpoint = "reports/credentialUserRegistrationDetails"
        data = self.make_graph_request(endpoint)
        if data:
            mfa_enabled_users = [user for user in data["value"] if user.get("isMfaRegistered")]
            total_users = len(data["value"])
            self.report.append(f"- MFA is enabled for {len(mfa_enabled_users)}/{total_users} users.")
            if len(mfa_enabled_users) < total_users:
                self.report.append("- Warning: Not all users have MFA enabled. Enforce MFA for better security.")

    def check_admin_accounts(self):
        """Check for privileged admin accounts."""
        self.report.append("\nChecking Admin Accounts:")
        endpoint = "directoryRoles"
        roles_data = self.make_graph_request(endpoint)
        if roles_data:
            admin_role = next((role for role in roles_data["value"] if role["displayName"] == "Global Administrator"), None)
            if admin_role:
                role_id = admin_role["id"]
                members_endpoint = f"directoryRoles/{role_id}/members"
                members_data = self.make_graph_request(members_endpoint)
                if members_data:
                    admin_accounts = [member["userPrincipalName"] for member in members_data["value"]]
                    self.report.append(f"- Found {len(admin_accounts)} Global Admin accounts: {', '.join(admin_accounts)}")
                    if len(admin_accounts) > 3:
                        self.report.append("- Warning: Too many Global Admin accounts. Reduce to 2-3 as per best practices.")

    def check_conditional_access_policies(self):
        """Check conditional access policies."""
        self.report.append("\nChecking Conditional Access Policies:")
        endpoint = "identity/conditionalAccess/policies"
        policies_data = self.make_graph_request(endpoint)
        if policies_data:
            active_policies = [policy for policy in policies_data["value"] if policy["state"] == "enabled"]
            self.report.append(f"- Found {len(active_policies)} active Conditional Access policies.")
            for policy in active_policies:
                self.report.append(f"  - Policy Name: {policy['displayName']}")
                self.report.append(f"    - State: {policy['state']}")
                self.report.append(f"    - Conditions: {json.dumps(policy['conditions'])}")

    def check_inactive_users(self):
        """Check for inactive users."""
        self.report.append("\nChecking Inactive Users:")
        endpoint = "users"
        users_data = self.make_graph_request(endpoint)
        if users_data:
            inactive_users = [
                user["userPrincipalName"]
                for user in users_data["value"]
                if "signInActivity" in user and user["signInActivity"].get("lastSignInDateTime") is None
            ]
            self.report.append(f"- Found {len(inactive_users)} inactive users.")
            if inactive_users:
                self.report.append(f"  - Inactive Users: {', '.join(inactive_users)}")

    def check_secure_score(self):
        """Check Microsoft Secure Score."""
        self.report.append("\nChecking Secure Score:")
        endpoint = "security/secureScores"
        score_data = self.make_graph_request(endpoint)
        if score_data:
            current_score = score_data["value"][0]["currentScore"]
            max_score = score_data["value"][0]["maxScore"]
            self.report.append(f"- Secure Score: {current_score}/{max_score} ({(current_score / max_score) * 100:.2f}%)")

    def check_teams_settings(self):
        """Check Microsoft Teams security settings."""
        self.report.append("\nChecking Microsoft Teams Settings:")
        endpoint = "teamwork/teams"
        teams_data = self.make_graph_request(endpoint)
        if teams_data:
            self.report.append(f"- Found {len(teams_data['value'])} Teams.")
            for team in teams_data["value"]:
                self.report.append(f"  - Team Name: {team['displayName']}")
                self.report.append(f"    - Visibility: {team['visibility']}")
                self.report.append(f"    - Is Archived: {team.get('isArchived', 'False')}")

    def check_data_retention_policies(self):
        """Check Data Retention Policies."""
        self.report.append("\nChecking Data Retention Policies:")
        endpoint = "compliance/retentionPolicies"
        policies_data = self.make_graph_request(endpoint)
        if policies_data:
            self.report.append(f"- Found {len(policies_data['value'])} Retention Policies.")
            for policy in policies_data["value"]:
                self.report.append(f"  - Policy Name: {policy['displayName']}")
                self.report.append(f"    - Status: {policy['status']}")
                self.report.append(f"    - Locations: {json.dumps(policy['locations'])}")

    def generate_report(self):
        """Generate a detailed security audit report."""
        self.report.append(f"Microsoft 365 Security Audit Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.report.append("=" * 50)
        try:
            self.get_access_token()
            self.check_mfa()
            self.check_admin_accounts()
            self.check_conditional_access_policies()
            self.check_inactive_users()
            self.check_secure_score()
            self.check_teams_settings()
            self.check_data_retention_policies()
        except Exception as e:
            self.report.append(f"Error during audit: {e}")
        finally:
            self.report.append("=" * 50)
            report_path = f"microsoft_365_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_path, "w") as report_file:
                report_file.write("\n".join(self.report))
            print(f"Security audit report generated: {report_path}")


if __name__ == "__main__":
    print("Starting Microsoft 365 Security Audit...")
    audit = Microsoft365SecurityAudit()
    audit.generate_report()
    print("Audit completed.")
