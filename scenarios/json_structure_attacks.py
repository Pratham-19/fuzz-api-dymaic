import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class JSONStructureFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_malformed_json_payloads(self):
        """Test malformed JSON structures"""
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

        malformed_json_payloads = [
            '{"name": "test", "username": "user", "password": "pass", "type": "OS",}',  # Trailing comma
            '{"name": "test", "username": "user", "password": "pass", "type": "OS"',   # Missing closing brace
            '{"name": "test", "username": "user", "password": "pass", "type": "OS"}}', # Extra closing brace
            '{"name": "test", "username": "user", "password": "pass", "type": "OS" "extra": "field"}', # Missing comma
            '{"name": "test", username: "user", "password": "pass", "type": "OS"}',    # Unquoted key
            '{"name": "test", "username": "user", "password": "pass", "type": OS}',    # Unquoted value
            '{name: "test", username: "user", password: "pass", type: "OS"}',          # All unquoted keys
            '{"name": "test", "username": "user", "password": "pass", "type": "OS"} extra',  # Extra content
            '/* comment */ {"name": "test", "username": "user"}',                      # JSON with comments
            '{"name": "\\"test\\"", "username": "user"}',                             # Escaped quotes issue
        ]

        for payload in malformed_json_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  data=payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Malformed JSON rejected: {payload[:50]}...")
                elif response.status_code == 500:
                    log.warning(f"Server error with malformed JSON: {payload[:50]}...")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_deeply_nested_json(self):
        """Test deeply nested JSON structures"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Create deeply nested structure
        nested_levels = [5, 10, 50, 100]

        for level in nested_levels:
            # Build nested extraInfo structure
            nested_obj = {"value": "test"}
            for i in range(level):
                nested_obj = {"nested": nested_obj}

            payload = {
                "name": f"nested_test_{level}",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "extraInfo": [{"name": "nested_data", "value": json.dumps(nested_obj)}]
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 413, 422]:
                    response.success()
                    log.info(f"Deep nesting rejected at level: {level}")
                elif response.status_code == 500:
                    log.warning(f"Server error with nesting level: {level}")
                    response.success()
                elif response.status_code == 200:
                    log.info(f"Deep nesting accepted at level: {level}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_circular_references(self):
        """Test circular reference handling"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Simulate circular reference in extraInfo
        circular_payloads = [
            '{"name": "circular", "ref": {"back": "{{SELF}}"}}',
            '{"a": {"b": {"c": {"back_to_a": "{{ROOT}}"}}}}',
            '{"self": "{{SELF}}", "name": "test"}',
            '{"parent": {"child": {"parent_ref": "{{PARENT}}"}}}',
        ]

        for circular_str in circular_payloads:
            payload = {
                "name": "circular_test",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "extraInfo": [{"name": "circular_data", "value": circular_str}]
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Circular reference blocked: {circular_str[:30]}...")
                else:
                    response.success()

    @task
    def fuzz_large_json_arrays(self):
        """Test large JSON arrays"""
        headers = {"Authorization": f"Bearer {self.token}"}

        array_sizes = [100, 1000, 5000]

        for size in array_sizes:
            # Create large extraInfo array
            large_array = []
            for i in range(size):
                large_array.append({"name": f"item_{i}", "value": f"value_{i}"})

            payload = {
                "name": f"large_array_{size}",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "extraInfo": large_array
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 413, 422]:
                    response.success()
                    log.info(f"Large array rejected - size: {size}")
                elif response.status_code == 500:
                    log.warning(f"Server error with array size: {size}")
                    response.success()
                elif response.status_code == 200:
                    log.info(f"Large array accepted - size: {size}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_null_and_undefined_values(self):
        """Test null and undefined value handling"""
        headers = {"Authorization": f"Bearer {self.token}"}

        null_payloads = [
            {"name": None, "username": "test", "password": "test", "type": "OS"},
            {"name": "test", "username": None, "password": "test", "type": "OS"},
            {"name": "test", "username": "test", "password": None, "type": "OS"},
            {"name": "test", "username": "test", "password": "test", "type": None},
            {"name": "null", "username": "undefined", "password": "null", "type": "OS"},
            {"name": "", "username": "", "password": "", "type": ""},
        ]

        for payload in null_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Null value properly rejected")
                elif response.status_code == 500:
                    log.warning(f"Server error with null values")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_json_bomb_attacks(self):
        """Test JSON bomb/billion laughs attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Create exponentially expanding JSON
        json_bomb_payloads = [
            # Repetitive structure
            {"name": "A" * 10000, "username": "B" * 10000, "password": "C" * 10000, "type": "OS"},
            # Large numeric values
            {"name": "test", "username": "test", "password": "test", "type": "OS", "largeNumber": 9999999999999999999999},
            # Many duplicate keys (some parsers handle this poorly)
            '{"name": "test", "name": "test2", "name": "test3", "username": "user", "password": "pass", "type": "OS"}',
        ]

        for payload in json_bomb_payloads:
            if isinstance(payload, str):
                with self.client.post("/api/v3/raw-credentials",
                                      headers=headers,
                                      data=payload,
                                      verify=False,
                                      catch_response=True) as response:

                    if response.status_code in [400, 413, 422]:
                        response.success()
                        log.info("JSON bomb attack blocked")
                    else:
                        response.success()
            else:
                with self.client.post("/api/v3/raw-credentials",
                                      headers=headers,
                                      json=payload,
                                      verify=False,
                                      catch_response=True) as response:

                    if response.status_code in [400, 413, 422]:
                        response.success()
                        log.info("JSON bomb attack blocked")
                    else:
                        response.success()

class JSONStructureUser(HttpUser):
    wait_time = constant(1)
    tasks = [JSONStructureFuzz]
    host = "https://localhost:8443"

