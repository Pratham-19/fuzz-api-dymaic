import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class SQLInjectionFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_sql_injection_credential_name(self):
        """Test SQL injection in credential name field"""
        headers = {"Authorization": f"Bearer {self.token}"}

        sql_payloads = [
            "'; DROP TABLE credentials; --",
            "admin'/*",
            "1' OR '1'='1",
            "'; DELETE FROM users; --",
            "' UNION SELECT * FROM information_schema.tables --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' OR 1=1 --",
            "admin'; INSERT INTO users VALUES ('hacker','pass'); --"
        ]

        for payload in sql_payloads:
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

                if response.status_code in [400, 422, 500]:
                    response.success()
                    log.info(f"SQL injection blocked: {payload}")
                elif response.status_code == 200:
                    log.warning(f"Potential SQL injection vulnerability: {payload}")
                    response.success()
                else:
                    response.success()

class SQLInjectionUser(HttpUser):
    wait_time = constant(1)
    tasks = [SQLInjectionFuzz]
    host = "https://localhost:8443"
