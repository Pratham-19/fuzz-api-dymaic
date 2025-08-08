import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class CORSSecurityFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_cors_origin_bypass(self):
        """Test CORS origin bypass techniques"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Various Origin header bypass attempts
        malicious_origins = [
            "https://evil.com",
            "http://attacker.net",
            "https://localhost:8443.evil.com",
            "https://localhost:8443",  # Correct origin
            "https://localhostX8443",  # Typosquatting
            "https://localhost:8443#evil.com",
            "https://localhost:8443@evil.com",
            "https://localhost:8443.evil.com",
            "null",
            "",
            "https://localhost:8443\r\nOrigin: https://evil.com",
            "https://localhost:8443 evil.com",
            "https://sub.localhost:8443",
            "https://localhost:8443/",
            "https://localhost:8443.",
            "https://localhost:8443%00.evil.com",
            "file://",
            "data:",
            "javascript:",
        ]

        for origin in malicious_origins:
            headers = {**base_headers, "Origin": origin}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                cors_header = response.headers.get("Access-Control-Allow-Origin")
                if cors_header:
                    if cors_header == "*" or cors_header == origin:
                        log.warning(f"CORS bypass successful with origin: {origin}")
                    else:
                        log.info(f"CORS properly configured for origin: {origin}")
                    response.success()
                else:
                    log.info(f"No CORS header for origin: {origin}")
                    response.success()

    @task
    def fuzz_cors_preflight_bypass(self):
        """Test CORS preflight bypass techniques"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Test preflight OPTIONS requests
        preflight_tests = [
            {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type"
            },
            {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "authorization"
            },
            {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "authorization,x-admin"
            },
            {
                "Origin": "null",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization"
            },
        ]

        for preflight_headers in preflight_tests:
            headers = {**base_headers, **preflight_headers}

            with self.client.options("/api/v3/raw-credentials",
                                     headers=headers,
                                     verify=False,
                                     catch_response=True) as response:

                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                allow_methods = response.headers.get("Access-Control-Allow-Methods")
                allow_headers = response.headers.get("Access-Control-Allow-Headers")

                if allow_origin and (allow_origin == "*" or allow_origin == preflight_headers["Origin"]):
                    log.warning(f"Preflight bypass with origin: {preflight_headers['Origin']}")

                log.info(f"Preflight response - Origin: {allow_origin}, Methods: {allow_methods}, Headers: {allow_headers}")
                response.success()

    @task
    def fuzz_cors_credential_inclusion(self):
        """Test CORS with credentials inclusion"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Test different origins with credentials
        credential_tests = [
            {"Origin": "https://evil.com"},
            {"Origin": "https://localhost:8443"},
            {"Origin": "null"},
            {"Origin": "https://sub.localhost:8443"},
        ]

        for test_headers in credential_tests:
            headers = {**base_headers, **test_headers}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                allow_credentials = response.headers.get("Access-Control-Allow-Credentials")

                if allow_origin == "*" and allow_credentials == "true":
                    log.warning("Dangerous CORS config: wildcard origin with credentials")

                if allow_origin == test_headers["Origin"] and allow_credentials == "true":
                    log.warning(f"CORS allows credentials for origin: {test_headers['Origin']}")

                response.success()

    @task
    def fuzz_cors_header_injection(self):
        """Test CORS header injection attacks"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Header injection attempts in Origin
        injection_origins = [
            "https://evil.com\r\nAccess-Control-Allow-Origin: *",
            "https://evil.com\nSet-Cookie: admin=true",
            "https://evil.com\r\nX-Admin: true",
            "https://evil.com\x00evil-injected-header",
            "https://evil.com\u2028injected-header: true",
            "https://evil.com%0d%0aAccess-Control-Allow-Origin: *",
        ]

        for injection_origin in injection_origins:
            headers = {**base_headers, "Origin": injection_origin}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                # Check if injection was successful by looking for unexpected headers
                response_headers = dict(response.headers)
                suspicious_headers = ["X-Admin", "Set-Cookie"]

                for suspicious in suspicious_headers:
                    if suspicious in response_headers:
                        log.warning(f"Header injection successful: {suspicious}")

                response.success()

    @task
    def fuzz_cors_method_override(self):
        """Test CORS with HTTP method override"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Method override with CORS
        method_override_tests = [
            {
                "Origin": "https://evil.com",
                "X-HTTP-Method-Override": "DELETE"
            },
            {
                "Origin": "https://evil.com",
                "X-HTTP-Method": "PUT"
            },
            {
                "Origin": "https://evil.com",
                "_method": "PATCH"
            },
        ]

        credential_data = {
            "name": "cors_method_test",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        for test_headers in method_override_tests:
            headers = {**base_headers, **test_headers}

            # Use POST but try to override to different method
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                if allow_origin and allow_origin != "null":
                    log.info(f"Method override with CORS allowed for: {test_headers['Origin']}")

                response.success()

    @task
    def fuzz_cors_subdomain_bypass(self):
        """Test CORS subdomain bypass techniques"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Subdomain bypass attempts
        subdomain_tests = [
            "https://api.localhost:8443",
            "https://admin.localhost:8443",
            "https://test.localhost:8443",
            "https://dev.localhost:8443",
            "https://staging.localhost:8443",
            "https://internal.localhost:8443",
            "https://secure.localhost:8443",
            "https://evil.localhost:8443",
            "https://attacker.localhost:8443",
        ]

        for subdomain in subdomain_tests:
            headers = {**base_headers, "Origin": subdomain}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                if allow_origin == subdomain:
                    log.warning(f"Subdomain bypass successful: {subdomain}")
                elif allow_origin == "*":
                    log.warning(f"Wildcard CORS allows any subdomain: {subdomain}")

                response.success()

    @task
    def fuzz_cors_port_bypass(self):
        """Test CORS port bypass techniques"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Port-based bypass attempts
        port_tests = [
            "https://localhost:8080",
            "https://localhost:80",
            "https://localhost:443",
            "https://localhost:3000",
            "https://localhost:8000",
            "https://localhost:9000",
            "https://localhost:8443",  # Same port as API
            "http://localhost:8443",   # Different protocol
            "https://localhost",       # No port specified
        ]

        for port_origin in port_tests:
            headers = {**base_headers, "Origin": port_origin}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                if allow_origin == port_origin:
                    log.info(f"Port-based origin allowed: {port_origin}")
                elif allow_origin == "*":
                    log.warning(f"Wildcard CORS allows any port: {port_origin}")

                response.success()

    @task
    def fuzz_cors_protocol_bypass(self):
        """Test CORS protocol bypass techniques"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Protocol-based bypass attempts
        protocol_tests = [
            "http://localhost:8443",     # HTTP instead of HTTPS
            "ftp://localhost:8443",      # FTP protocol
            "file://localhost:8443",     # File protocol
            "data://localhost:8443",     # Data protocol
            "javascript://localhost:8443", # JavaScript protocol
            "chrome-extension://localhost:8443", # Extension protocol
            "moz-extension://localhost:8443",    # Firefox extension
        ]

        for protocol_origin in protocol_tests:
            headers = {**base_headers, "Origin": protocol_origin}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                allow_origin = response.headers.get("Access-Control-Allow-Origin")
                if allow_origin == protocol_origin:
                    log.warning(f"Protocol bypass successful: {protocol_origin}")
                elif allow_origin == "*":
                    log.warning(f"Wildcard CORS allows any protocol: {protocol_origin}")

                response.success()

class CORSSecurityUser(HttpUser):
    wait_time = constant(1)
    tasks = [CORSSecurityFuzz]
    host = "https://localhost:8443"
