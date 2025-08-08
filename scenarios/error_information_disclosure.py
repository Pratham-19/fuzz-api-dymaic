import json
import logging
import random
import string
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class ErrorInformationFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    def analyze_error_response(self, response, test_name):
        """Analyze error response for information disclosure"""
        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                error_data = response.json()

                # Check for sensitive information in error messages
                sensitive_indicators = [
                    "sql", "database", "jdbc", "oracle", "mysql", "postgres", "mongodb",
                    "stack trace", "exception", "java.", "com.", "org.",
                    "file not found", "path", "directory", "c:\\", "/usr/", "/etc/",
                    "internal server error", "debug", "stacktrace",
                    "username", "password", "token", "secret", "key",
                    "ldap", "active directory", "authentication failed",
                    "connection", "timeout", "network", "host", "port"
                ]

                error_message = str(error_data).lower()
                for indicator in sensitive_indicators:
                    if indicator in error_message:
                        log.warning(f"Sensitive info in {test_name}: {indicator} found in error")
                        break

                # Log detailed error for analysis
                log.info(f"{test_name} error response: {error_data}")

            else:
                # Check HTML error pages for information disclosure
                if response.text:
                    html_content = response.text.lower()
                    if any(term in html_content for term in ["stack trace", "exception", "debug", "internal error"]):
                        log.warning(f"Detailed error page in {test_name}")
        except:
            pass

    @task
    def fuzz_authentication_error_disclosure(self):
        """Test authentication error information disclosure"""

        # Various authentication scenarios to trigger different errors
        auth_tests = [
            # Wrong username
            {"username": "nonexistent_user", "password": "anypassword"},

            # Wrong password
            {"username": "admin", "password": "wrongpassword"},

            # SQL injection in username
            {"username": "admin'; DROP TABLE users; --", "password": "password"},

            # XSS in username
            {"username": "<script>alert('xss')</script>", "password": "password"},

            # Very long username
            {"username": "a" * 1000, "password": "password"},

            # Empty credentials
            {"username": "", "password": ""},

            # Null values
            {"username": None, "password": None},

            # Special characters
            {"username": "admin@domain.com", "password": "pass@word!"},

            # Unicode characters
            {"username": "admin\u0000", "password": "pass\u0000"},
        ]

        for auth_data in auth_tests:
            with self.client.post("/api/v3/login",
                                  json=auth_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code == 401:
                    self.analyze_error_response(response, f"Auth test: {auth_data['username']}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_input_validation_errors(self):
        """Test input validation error disclosure"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Invalid input tests to trigger validation errors
        validation_tests = [
            # Invalid credential type
            {
                "name": "test",
                "username": "user",
                "password": "pass",
                "type": "INVALID_TYPE_12345"
            },

            # Missing required fields
            {
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # Invalid data types
            {
                "name": 12345,
                "username": ["array"],
                "password": {"object": "value"},
                "type": None
            },

            # Extremely long values
            {
                "name": "a" * 10000,
                "username": "b" * 10000,
                "password": "c" * 10000,
                "type": "OS"
            },

            # Binary data
            {
                "name": "\x00\x01\x02\x03",
                "username": "\xff\xfe\xfd",
                "password": "test",
                "type": "OS"
            },
        ]

        for test_data in validation_tests:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=test_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    self.analyze_error_response(response, f"Validation test: {type(test_data.get('name'))}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_database_error_disclosure(self):
        """Test database error information disclosure"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Payloads likely to trigger database errors
        db_error_tests = [
            # SQL injection attempts
            {
                "name": "'; DROP TABLE credentials; SELECT * FROM users WHERE '1'='1",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # Unicode SQL injection
            {
                "name": "\u0027; DROP TABLE users; --",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # Database function calls
            {
                "name": "'; SELECT version(); --",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # NoSQL injection
            {
                "name": "'; return db.users.find(); var end='",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },
        ]

        for test_data in db_error_tests:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=test_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422, 500]:
                    self.analyze_error_response(response, f"DB error test: SQL injection")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_ldap_error_disclosure(self):
        """Test LDAP error information disclosure"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # LDAP configuration errors
        ldap_error_tests = [
            # Invalid LDAP host
            {
                "host": "nonexistent.ldap.server.invalid",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                }
            },

            # Invalid port
            {
                "host": "localhost",
                "port": 99999,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                }
            },

            # Invalid selector
            {
                "host": "localhost",
                "port": 389,
                "selector": "invalid.domain.that.does.not.exist",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                }
            },

            # LDAP injection in selector
            {
                "host": "localhost",
                "port": 389,
                "selector": "test.com)(objectClass=*",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                }
            },
        ]

        for test_data in ldap_error_tests:
            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=test_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422, 500]:
                    self.analyze_error_response(response, f"LDAP error test: {test_data.get('host')}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_file_system_error_disclosure(self):
        """Test file system error information disclosure"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # File system related errors
        file_error_tests = [
            # Path traversal attempts
            {
                "name": "../../etc/passwd",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # Windows paths
            {
                "name": "C:\\Windows\\System32\\config\\SAM",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # UNC paths
            {
                "name": "\\\\server\\share\\file",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },

            # File URI
            {
                "name": "file:///etc/shadow",
                "username": "user",
                "password": "pass",
                "type": "OS"
            },
        ]

        for test_data in file_error_tests:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=test_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422, 500]:
                    self.analyze_error_response(response, f"File error test: path traversal")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_network_error_disclosure(self):
        """Test network error information disclosure"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Network connectivity errors
        network_error_tests = [
            # Non-routable IP
            {
                "host": "192.0.2.1",  # TEST-NET-1
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {"name": "user", "password": "pass"}
            },

            # Localhost with closed port
            {
                "host": "127.0.0.1",
                "port": 12345,
                "selector": "test.com",
                "serviceAccount": {"name": "user", "password": "pass"}
            },

            # IPv6 addresses
            {
                "host": "::1",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {"name": "user", "password": "pass"}
            },

            # Invalid IP format
            {
                "host": "999.999.999.999",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {"name": "user", "password": "pass"}
            },
        ]

        for test_data in network_error_tests:
            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=test_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422, 500]:
                    self.analyze_error_response(response, f"Network error test: {test_data.get('host')}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_server_error_disclosure(self):
        """Test server error information disclosure"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Requests designed to trigger server errors
        server_error_tests = [
            # Malformed JSON that might crash parser
            '{"name": "test", "username": "user", "password": "pass", "type": "OS"} extra',

            # Recursive references
            '{"name": "test", "ref": {"parent": {"child": {"grandparent": "{{CIRCULAR}}"}}}}',

            # Extremely nested JSON
            '{"a":' * 100 + '"test"' + '}' * 100,

            # Large payload
            json.dumps({"name": "A" * 100000, "username": "user", "password": "pass", "type": "OS"}),
        ]

        for payload in server_error_tests:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  data=payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code == 500:
                    self.analyze_error_response(response, "Server error test")
                    response.success()
                else:
                    response.success()

class ErrorInformationUser(HttpUser):
    wait_time = constant(1)
    tasks = [ErrorInformationFuzz]
    host = "https://localhost:8443"
