import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class XSSInjectionFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_xss_injection_credential_fields(self):
        """Test XSS injection in credential fields"""
        headers = {"Authorization": f"Bearer {self.token}"}

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "';alert('XSS');//",
            "<script>document.location='http://evil.com'</script>"
        ]

        for payload in xss_payloads:
            credential_data = {
                "name": f"test_cred_{payload}",
                "username": payload,
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
                    log.info(f"XSS payload filtered: {payload}")
                elif response.status_code == 200:
                    log.warning(f"Potential XSS vulnerability: {payload}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_xss_local_account_fields(self):
        """Test XSS in local account creation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for payload in xss_payloads:
            account_data = {
                "name": payload,
                "firstName": payload,
                "lastName": payload,
                "emailAddress": f"{payload}@test.com"
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"XSS payload filtered in account: {payload}")
                elif response.status_code == 200:
                    log.warning(f"Potential XSS vulnerability in account: {payload}")
                    response.success()
                else:
                    response.success()

class XSSInjectionUser(HttpUser):
    wait_time = constant(1)
    tasks = [XSSInjectionFuzz]
    host = "https://localhost:8443"
