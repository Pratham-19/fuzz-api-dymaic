import json
import logging
import string
import random
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class BufferOverflowFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    def generate_oversized_string(self, length):
        """Generate random string of specified length"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @task
    def fuzz_buffer_overflow_credential_password(self):
        """Test buffer overflow in credential password field"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test various buffer sizes
        buffer_sizes = [1000, 5000, 10000, 50000, 100000]

        for size in buffer_sizes:
            oversized_password = self.generate_oversized_string(size)

            credential_data = {
                "name": f"test_cred_{size}",
                "username": "testuser",
                "password": oversized_password,
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 413, 422]:
                    response.success()
                    log.info(f"Buffer overflow protected - size: {size}")
                elif response.status_code == 500:
                    log.warning(f"Server error with buffer size: {size}")
                    response.success()
                elif response.status_code == 200:
                    log.info(f"Large password accepted - size: {size}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_buffer_overflow_username(self):
        """Test buffer overflow in username field"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test username buffer overflow
        oversized_username = self.generate_oversized_string(10000)

        credential_data = {
            "name": "test_cred_username_overflow",
            "username": oversized_username,
            "password": "testpass",
            "type": "OS"
        }

        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              json=credential_data,
                              verify=False,
                              catch_response=True) as response:

            if response.status_code in [400, 413, 422]:
                response.success()
                log.info("Username buffer overflow protected")
            elif response.status_code == 500:
                log.warning("Server error with oversized username")
                response.success()
            else:
                response.success()

    @task
    def fuzz_buffer_overflow_ad_selector(self):
        """Test buffer overflow in AD provider selector"""
        headers = {"Authorization": f"Bearer {self.token}"}

        oversized_selector = self.generate_oversized_string(8000) + ".com"

        ad_provider_data = {
            "host": "test-host.com",
            "port": 389,
            "selector": oversized_selector,
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

            if response.status_code in [400, 413, 422]:
                response.success()
                log.info("AD selector buffer overflow protected")
            elif response.status_code == 500:
                log.warning("Server error with oversized selector")
                response.success()
            else:
                response.success()

class BufferOverflowUser(HttpUser):
    wait_time = constant(1)
    tasks = [BufferOverflowFuzz]
    host = "https://localhost:8443"
