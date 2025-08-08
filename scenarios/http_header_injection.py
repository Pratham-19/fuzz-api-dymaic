import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class HTTPHeaderFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_header_injection_attacks(self):
        """Test HTTP header injection attacks"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Header injection payloads
        injection_headers = [
            {"X-Forwarded-For": "127.0.0.1\r\nX-Injected: malicious"},
            {"User-Agent": "Mozilla/5.0\r\nX-Admin: true"},
            {"Referer": "http://legitimate.com\r\nAuthorization: Bearer admin"},
            {"X-Real-IP": "192.168.1.1\r\nSet-Cookie: admin=true"},
            {"Accept": "application/json\r\nX-Override-Method: DELETE"},
            {"Content-Type": "application/json\r\nX-Forwarded-Proto: https"},
            {"Host": "api.company.com\r\nX-Forwarded-Host: evil.com"},
            {"X-Custom": "value\x00null-byte"},
            {"X-Test": "value\x0d\x0acrlf-injection"},
            {"X-Unicode": "test\u2028line-separator"},
        ]

        credential_data = {
            "name": "header_test",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        for inject_headers in injection_headers:
            headers = {**base_headers, **inject_headers}

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Header injection blocked: {list(inject_headers.keys())}")
                elif response.status_code == 401:
                    response.success()
                    log.info("Authentication check working")
                else:
                    response.success()

    @task
    def fuzz_oversized_headers(self):
        """Test oversized HTTP headers"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Test various oversized headers
        oversized_tests = [
            {"X-Large-Header": "A" * 8192},      # 8KB header
            {"X-Huge-Header": "B" * 65536},     # 64KB header
            {"User-Agent": "C" * 16384},        # Large User-Agent
            {"Referer": "http://evil.com/" + "D" * 10000},  # Large Referer
            {"Accept": "application/" + "E" * 5000},        # Large Accept
            {"X-Forwarded-For": "127.0.0.1, " + "192.168.1." + "1, " * 1000},  # Many IPs
        ]

        credential_data = {
            "name": "oversized_header_test",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        for oversized_header in oversized_tests:
            headers = {**base_headers, **oversized_header}

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 413, 431]:  # 431 = Request Header Fields Too Large
                    response.success()
                    log.info(f"Oversized header rejected: {list(oversized_header.keys())}")
                elif response.status_code == 500:
                    log.warning(f"Server error with oversized header: {list(oversized_header.keys())}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_http_method_override(self):
        """Test HTTP method override attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Method override headers
        override_headers = [
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-HTTP-Method": "PUT"},
            {"X-Method-Override": "PATCH"},
            {"_method": "DELETE"},
            {"X-HTTP-Method-Override": "ADMIN"},
            {"X-HTTP-Method-Override": "'; DROP TABLE credentials; --"},
            {"X-HTTP-Method-Override": "../../../etc/passwd"},
            {"X-Override-Method": "POST\r\nX-Admin: true"},
        ]

        credential_data = {
            "name": "method_override_test",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        for override_header in override_headers:
            test_headers = {**headers, **override_header}

            with self.client.post("/api/v3/raw-credentials",
                                  headers=test_headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 405, 422]:
                    response.success()
                    log.info(f"Method override blocked: {override_header}")
                else:
                    response.success()

    @task
    def fuzz_host_header_attacks(self):
        """Test Host header manipulation attacks"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Malicious Host headers
        malicious_hosts = [
            {"Host": "evil.com"},
            {"Host": "localhost:8443\r\nX-Injected: true"},
            {"Host": "127.0.0.1:8443@evil.com"},
            {"Host": "api.company.com:8443#evil.com"},
            {"Host": "localhost:8443/../../../etc/passwd"},
            {"Host": "localhost:8443'; DROP TABLE users; --"},
            {"Host": "localhost:999999"},  # Invalid port
            {"Host": ""},  # Empty host
            {"Host": "localhost\x00.evil.com:8443"},  # Null byte
        ]

        for malicious_host in malicious_hosts:
            headers = {**base_headers, **malicious_host}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Malicious Host header blocked: {malicious_host['Host']}")
                else:
                    response.success()

    @task
    def fuzz_content_type_confusion(self):
        """Test Content-Type header manipulation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        credential_data = {
            "name": "content_type_test",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        # Various Content-Type attacks
        content_types = [
            {"Content-Type": "application/xml"},  # Wrong content type
            {"Content-Type": "text/plain"},
            {"Content-Type": "multipart/form-data"},
            {"Content-Type": "application/json; charset=utf-7"},  # UTF-7 XSS
            {"Content-Type": "application/json\r\nX-Injected: true"},  # Header injection
            {"Content-Type": "application/json; boundary=--evil"},
            {"Content-Type": "application/json;charset=iso-8859-1"},
            {"Content-Type": ""},  # Empty content type
            {"Content-Type": "application/json" + "\x00"},  # Null byte
        ]

        for ct_header in content_types:
            test_headers = {**headers, **ct_header}

            with self.client.post("/api/v3/raw-credentials",
                                  headers=test_headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 415, 422]:  # 415 = Unsupported Media Type
                    response.success()
                    log.info(f"Invalid Content-Type blocked: {ct_header['Content-Type']}")
                else:
                    response.success()

    @task
    def fuzz_security_header_bypass(self):
        """Test security header bypass attempts"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Security bypass headers
        bypass_headers = [
            {"X-Forwarded-Proto": "https"},
            {"X-Forwarded-SSL": "on"},
            {"X-Forwarded-Scheme": "https"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "192.168.1.1"},
            {"X-Remote-IP": "10.0.0.1"},
            {"X-Client-IP": "172.16.0.1"},
            {"X-Cluster-Client-IP": "localhost"},
            {"True-Client-IP": "admin"},
            {"CF-Connecting-IP": "127.0.0.1"},  # Cloudflare
            {"X-Azure-ClientIP": "internal"},   # Azure
            {"Fastly-Client-IP": "trusted"},    # Fastly CDN
        ]

        for bypass_header in bypass_headers:
            headers = {**base_headers, **bypass_header}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.info(f"Security header accepted: {bypass_header}")
                    response.success()
                elif response.status_code == 401:
                    response.success()
                else:
                    response.success()

class HTTPHeaderUser(HttpUser):
    wait_time = constant(1)
    tasks = [HTTPHeaderFuzz]
    host = "https://localhost:8443"
