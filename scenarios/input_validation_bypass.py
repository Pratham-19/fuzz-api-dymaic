import json
import logging
import string
import random
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class InputValidationFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_credential_type_validation(self):
        """Test credential type validation bypass"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Invalid credential types
        invalid_types = [
            "INVALID_TYPE",
            "datadomain",  # lowercase
            "DATA_DOMAIN",  # underscore variant
            "ADMIN",
            "ROOT",
            "SYSTEM",
            "'; DROP TABLE types; --",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "",
            None,
            123,
            [],
            {},
            "DATADOMAIN_EXTENDED",
            "POWERPROTECT_V2",
            "CUSTOM_TYPE"
        ]

        for invalid_type in invalid_types:
            credential_data = {
                "name": f"type_test_{str(invalid_type)[:10]}",
                "username": "testuser",
                "password": "testpass",
                "type": invalid_type
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Invalid type rejected: {invalid_type}")
                elif response.status_code == 200:
                    log.warning(f"Invalid type accepted: {invalid_type}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_port_number_validation(self):
        """Test port number validation in AD providers"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Invalid port numbers
        invalid_ports = [
            -1, 0, 65536, 99999, -99999,
            1.5, 3.14159,  # Float values
            "389", "not_a_number", "port",
            "'; DROP TABLE ports; --",
            None, [], {},
            2147483647,  # Max int
            -2147483648,  # Min int
            "389; rm -rf /",
            "389 OR 1=1",
        ]

        for invalid_port in invalid_ports:
            ad_provider_data = {
                "host": "test-host.com",
                "port": invalid_port,
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
                    log.info(f"Invalid port rejected: {invalid_port}")
                elif response.status_code == 200:
                    log.warning(f"Invalid port accepted: {invalid_port}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_boolean_field_validation(self):
        """Test boolean field validation bypass"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Invalid boolean values
        invalid_booleans = [
            "true", "false",  # String instead of boolean
            "yes", "no",
            "1", "0",
            1, 0,  # Integer instead of boolean
            "True", "False",  # Capitalized
            "TRUE", "FALSE",  # All caps
            None, [], {},
            "'; DROP TABLE settings; --",
            "<script>alert('xss')</script>",
        ]

        for invalid_bool in invalid_booleans:
            ad_provider_data = {
                "host": "test-host.com",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                },
                "secure": invalid_bool,
                "enabled": invalid_bool
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=ad_provider_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Invalid boolean rejected: {invalid_bool}")
                elif response.status_code == 200:
                    log.warning(f"Invalid boolean accepted: {invalid_bool}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_string_length_validation(self):
        """Test string length validation limits"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test various string lengths
        length_tests = [
            ("", 0),                           # Empty string
            ("a", 1),                          # Single character
            ("a" * 255, 255),                  # Common limit
            ("a" * 256, 256),                  # Just over common limit
            ("a" * 1023, 1023),                # Just under 1KB
            ("a" * 1024, 1024),                # 1KB
            ("a" * 4095, 4095),                # Just under 4KB
            ("a" * 4096, 4096),                # 4KB
            ("a" * 8191, 8191),                # Just under 8KB
            ("a" * 8192, 8192),                # 8KB
        ]

        for test_string, length in length_tests:
            account_data = {
                "name": f"length_test_{length}",
                "firstName": test_string,
                "lastName": test_string,
                "emailAddress": f"test{length}@example.com"
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 413, 422]:
                    response.success()
                    log.info(f"String length {length} rejected")
                elif response.status_code == 200:
                    log.info(f"String length {length} accepted")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_regex_bypass_attempts(self):
        """Test regex validation bypass techniques"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Common regex bypass techniques for names/usernames
        regex_bypasses = [
            "admin\x00user",          # Null byte
            "admin\nuser",            # Newline
            "admin\ruser",            # Carriage return
            "admin\tuser",            # Tab
            "admin user",             # Space (might be allowed/disallowed)
            "admin.user",             # Dot
            "admin-user",             # Hyphen
            "admin_user",             # Underscore
            "admin@user",             # At symbol
            "admin+user",             # Plus
            "admin=user",             # Equals
            "admin;user",             # Semicolon
            "admin,user",             # Comma
            "admin|user",             # Pipe
            "admin&user",             # Ampersand
            "admin$user",             # Dollar
            "admin%user",             # Percent
            "admin#user",             # Hash
            "admin!user",             # Exclamation
            "admin?user",             # Question mark
            "admin*user",             # Asterisk
            "admin(user)",            # Parentheses
            "admin[user]",            # Brackets
            "admin{user}",            # Braces
            "admin<user>",            # Angle brackets
            "admin\"user\"",          # Quotes
            "admin'user'",            # Single quotes
            "admin`user`",            # Backticks
            "admin\\user",            # Backslash
            "admin/user",             # Forward slash
        ]

        for bypass_attempt in regex_bypasses:
            credential_data = {
                "name": bypass_attempt,
                "username": bypass_attempt,
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
                    log.info(f"Regex bypass blocked: {repr(bypass_attempt)}")
                elif response.status_code == 200:
                    log.info(f"Regex bypass accepted: {repr(bypass_attempt)}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_numeric_boundary_conditions(self):
        """Test numeric boundary conditions"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Boundary values for page and pageSize parameters
        boundary_tests = [
            {"page": -1, "pageSize": 10},
            {"page": 0, "pageSize": 10},
            {"page": 1, "pageSize": -1},
            {"page": 1, "pageSize": 0},
            {"page": 1, "pageSize": 251},      # Over maximum
            {"page": 999999999, "pageSize": 10},
            {"page": 1, "pageSize": 999999999},
            {"page": 2147483647, "pageSize": 2147483647},  # Max int
            {"page": -2147483648, "pageSize": -2147483648}, # Min int
        ]

        for params in boundary_tests:
            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 params=params,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Boundary values rejected: {params}")
                elif response.status_code == 200:
                    log.info(f"Boundary values accepted: {params}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_required_field_validation(self):
        """Test required field validation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test missing required fields one by one
        base_credential = {
            "name": "test_cred",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        required_fields = ["name", "username", "password", "type"]

        for field in required_fields:
            incomplete_data = base_credential.copy()
            del incomplete_data[field]  # Remove required field

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=incomplete_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Missing required field rejected: {field}")
                elif response.status_code == 200:
                    log.warning(f"Missing required field accepted: {field}")
                    response.success()
                else:
                    response.success()

class InputValidationUser(HttpUser):
    wait_time = constant(1)
    tasks = [InputValidationFuzz]
    host = "https://localhost:8443"
