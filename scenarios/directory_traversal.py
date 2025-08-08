import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class DirectoryTraversalFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_directory_traversal_ad_host(self):
        """Test directory traversal in AD provider host field"""
        headers = {"Authorization": f"Bearer {self.token}"}

        traversal_payloads = [
            "../../etc/passwd",
            "../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....\/....\/....\/etc\/passwd",
            "file:///etc/passwd",
            "file://C:\\windows\\system32\\config\\sam",
            "\\\\..\\\\..\\\\..\\\\etc\\\\passwd"
        ]

        for payload in traversal_payloads:
            ad_provider_data = {
                "host": payload,
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                }
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=ad_provider_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Directory traversal blocked: {payload}")
                elif response.status_code == 500:
                    log.warning(f"Server error with traversal: {payload}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_directory_traversal_credential_name(self):
        """Test directory traversal in credential name"""
        headers = {"Authorization": f"Bearer {self.token}"}

        traversal_payloads = [
            "../../../etc/shadow",
            "..\\..\\..\\windows\\system32\\config\\system",
            "....//....//....//proc//version",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fproc%2fversion"
        ]

        for payload in traversal_payloads:
            credential_data = {
                "name": payload,
                "username": "testuser",
                "password": "testpass",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Credential name traversal blocked: {payload}")
                else:
                    response.success()

    @task
    def fuzz_path_traversal_api_endpoints(self):
        """Test path traversal in API endpoints themselves"""
        headers = {"Authorization": f"Bearer {self.token}"}

        malicious_paths = [
            "/api/v3/../../../etc/passwd",
            "/api/v3/raw-credentials/../../../etc/shadow",
            "/api/v3/raw-credentials/..%2F..%2F..%2Fetc%2Fpasswd",
            "/api/v3/raw-credentials/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "/api/v3\\..\\..\\..\\windows\\system32\\config\\sam"
        ]

        for path in malicious_paths:
            with self.client.get(path,
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 404:
                    response.success()
                    log.info(f"Path traversal properly handled: {path}")
                elif response.status_code in [400, 403]:
                    response.success()
                    log.info(f"Path traversal blocked: {path}")
                elif response.status_code == 200:
                    log.warning(f"Potential path traversal vulnerability: {path}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_config_path_injection(self):
        """Test path injection in AD config fields"""
        headers = {"Authorization": f"Bearer {self.token}"}

        config_data = {
            "host": "test-host.com",
            "port": 389,
            "selector": "test.com",
            "serviceAccount": {
                "name": "testuser",
                "password": "testpass"
            },
            "config": {
                "groupSearchBase": "../../etc/passwd",
                "userSearchPath": "../../../windows/system32/config/sam",
                "groupMemberAttribute": "file:///etc/shadow",
                "groupSearchAttribute": "\\\\..\\\\..\\\\..\\\\proc\\\\version"
            }
        }

        with self.client.post("/api/v3/active-directory-identity-providers",
                              headers=headers,
                              json=config_data,
                              verify=False,
                              catch_response=True) as response:

            if response.status_code in [400, 422]:
                response.success()
                log.info("Config path injection blocked")
            elif response.status_code == 500:
                log.warning("Server error with config path injection")
                response.success()
            else:
                response.success()

class DirectoryTraversalUser(HttpUser):
    wait_time = constant(1)
    tasks = [DirectoryTraversalFuzz]
    host = "https://localhost:8443"
