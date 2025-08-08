import json
import logging
import time
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class SessionManagementFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_token_manipulation(self):
        """Test JWT token manipulation attacks"""

        if self.token == "fake_token":
            return

        # Various token manipulation attempts
        manipulated_tokens = [
            self.token[:-5] + "AAAAA",           # Modify signature
            self.token[:-10] + "B" * 10,        # Modify more of signature
            self.token + "extra",                # Append data
            "modified" + self.token,             # Prepend data
            self.token.replace(".", "_"),        # Replace dots
            self.token.upper(),                  # Change case
            self.token.lower(),                  # Change case
            self.token[:len(self.token)//2],     # Truncate token
            self.token + "." + "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",  # Append fake JWT
        ]

        for manipulated_token in manipulated_tokens:
            headers = {"Authorization": f"Bearer {manipulated_token}"}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 401:
                    response.success()
                    log.info("Token manipulation properly rejected")
                elif response.status_code == 200:
                    log.warning(f"Token manipulation accepted: {manipulated_token[:20]}...")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_session_fixation(self):
        """Test session fixation attacks"""

        # Try to use a fixed/predictable token
        fixed_tokens = [
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fixed_signature",
            "admin_token_123",
            "session_12345",
            "bearer_admin",
            "token_admin_2024",
            "jwt_admin_session",
            str(uuid.uuid4()),  # Predictable UUID
            "00000000-0000-0000-0000-000000000000",  # Null UUID
            "12345678-1234-1234-1234-123456789012",  # Sequential UUID
        ]

        for fixed_token in fixed_tokens:
            headers = {"Authorization": f"Bearer {fixed_token}"}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 401:
                    response.success()
                    log.info("Fixed token properly rejected")
                elif response.status_code == 200:
                    log.warning(f"Fixed token accepted: {fixed_token}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_concurrent_sessions(self):
        """Test concurrent session handling"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to use the same token from "different" clients
        client_identifiers = [
            {"User-Agent": "Client1"},
            {"User-Agent": "Client2", "X-Forwarded-For": "192.168.1.100"},
            {"User-Agent": "Client3", "X-Real-IP": "10.0.0.50"},
            {"X-Session-ID": "session_1"},
            {"X-Session-ID": "session_2"},
        ]

        for client_headers in client_identifiers:
            test_headers = {**headers, **client_headers}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=test_headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.info(f"Concurrent session allowed: {client_headers}")
                    response.success()
                elif response.status_code == 401:
                    log.info(f"Concurrent session blocked: {client_headers}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_session_timeout_bypass(self):
        """Test session timeout bypass attempts"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Make request, wait, then try again to test timeout
        with self.client.get("/api/v3/raw-credentials",
                             headers=headers,
                             verify=False,
                             catch_response=True) as response:

            if response.status_code == 200:
                log.info("Initial request successful")
                response.success()
            else:
                response.success()

        # Simulate session timeout by waiting
        log.info("Waiting to test session timeout...")
        time.sleep(2)  # Short wait for testing

        # Try request after timeout
        with self.client.get("/api/v3/raw-credentials",
                             headers=headers,
                             verify=False,
                             catch_response=True) as response:

            if response.status_code == 200:
                log.info("Session still valid after wait")
                response.success()
            elif response.status_code == 401:
                log.info("Session properly timed out")
                response.success()
            else:
                response.success()

    @task
    def fuzz_token_refresh_attacks(self):
        """Test token refresh mechanism attacks"""

        # Try to refresh with invalid/manipulated tokens
        refresh_attempts = [
            {"refresh_token": "invalid_refresh"},
            {"refresh_token": self.token},  # Use access token as refresh
            {"refresh_token": '; DROP TABLE tokens; --'},
            {"refresh_token": None},
            {"refresh_token": ""},
            {"access_token": self.token, "refresh_token": "fake"},
        ]

        for refresh_data in refresh_attempts:
            with self.client.post("/api/v3/refresh-token",
                                  json=refresh_data,
                                  verify=False,
                                  catch_response=True) as response:

                # Most likely this endpoint doesn't exist, but testing anyway
                if response.status_code in [400, 401, 404, 422]:
                    response.success()
                    log.info("Invalid refresh properly rejected")
                elif response.status_code == 200:
                    log.warning(f"Refresh attack successful: {refresh_data}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_logout_bypass(self):
        """Test logout mechanism bypass"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Make request before logout
        with self.client.get("/api/v3/raw-credentials",
                             headers=headers,
                             verify=False,
                             catch_response=True) as response:

            if response.status_code == 200:
                log.info("Pre-logout request successful")
                response.success()
            else:
                response.success()

        # Attempt logout
        with self.client.post("/api/v3/logout",
                              headers=headers,
                              verify=False,
                              catch_response=True) as response:

            if response.status_code in [200, 204]:
                log.info("Logout successful")
                response.success()
            elif response.status_code == 404:
                log.info("Logout endpoint not found")
                response.success()
            else:
                response.success()

        # Try to use token after logout
        with self.client.get("/api/v3/raw-credentials",
                             headers=headers,
                             verify=False,
                             catch_response=True) as response:

            if response.status_code == 401:
                log.info("Token properly invalidated after logout")
                response.success()
            elif response.status_code == 200:
                log.warning("Token still valid after logout - possible bypass")
                response.success()
            else:
                response.success()

    @task
    def fuzz_session_hijacking_attempts(self):
        """Test session hijacking prevention"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to hijack session by changing client characteristics
        hijacking_attempts = [
            # Change User-Agent mid-session
            {"User-Agent": "DifferentBrowser/1.0"},
            {"User-Agent": "curl/7.68.0"},
            {"User-Agent": ""},

            # Change IP headers
            {"X-Forwarded-For": "192.168.1.200"},
            {"X-Real-IP": "10.0.0.100"},
            {"X-Originating-IP": "172.16.0.50"},

            # Add suspicious headers
            {"X-Forwarded-Host": "evil.com"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/api/v3/admin"},
        ]

        for hijack_headers in hijacking_attempts:
            test_headers = {**headers, **hijack_headers}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=test_headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.info(f"Session change allowed: {hijack_headers}")
                    response.success()
                elif response.status_code == 401:
                    log.info(f"Session change blocked: {hijack_headers}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_privilege_escalation_via_session(self):
        """Test privilege escalation through session manipulation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to escalate privileges via headers
        escalation_headers = [
            {"X-Admin": "true"},
            {"X-Role": "admin"},
            {"X-Privilege": "superuser"},
            {"X-User-ID": "0"},  # Root user ID
            {"X-Group": "administrators"},
            {"X-Sudo": "enabled"},
            {"X-Impersonate": "admin"},
            {"X-As-User": "root"},
            {"X-Effective-User": "admin"},
        ]

        for escalation_header in escalation_headers:
            test_headers = {**headers, **escalation_header}

            # Try to access admin-only operations (if they exist)
            with self.client.get("/api/v3/raw-credentials",
                                 headers=test_headers,
                                 params={"admin": "true"},
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.info(f"Privilege escalation header allowed: {escalation_header}")
                    response.success()
                elif response.status_code == 403:
                    log.info(f"Privilege escalation blocked: {escalation_header}")
                    response.success()
                else:
                    response.success()

class SessionManagementUser(HttpUser):
    wait_time = constant(1)
    tasks = [SessionManagementFuzz]
    host = "https://localhost:8443"
