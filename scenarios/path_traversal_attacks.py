import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events
import sys

stat_file = open('/tmp/path_traversal_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class PathTraversalAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        PathTraversalAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        PathTraversalAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = PathTraversalAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = PathTraversalAttacks.json.payload(api_call="on_start")
        version = PathTraversalAttacks.json.version(api_call="on_start")
        uri = PathTraversalAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_path_traversal_in_ids(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Path traversal payloads for ID parameters
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc//passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%5c..%5c..%5cetc%5cpasswd",
            "/etc/passwd%00",
            "....\/....\/....\/etc\/passwd",
            "file:///etc/passwd"
        ]

        for payload in traversal_payloads:
            # Test path traversal in credential ID
            with self.client.get(f"/api/v3/raw-credentials/{payload}",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200 and ("root:" in response.text or "admin:" in response.text):
                    log.critical(f"CRITICAL: Path traversal successful: {payload}")
                    response.success()
                else:
                    log.info(f"Path traversal blocked: {response.status_code}")

            # Test path traversal in DELETE requests
            with self.client.delete(f"/api/v3/raw-credentials/{payload}",
                                    headers=headers,
                                    verify=False,
                                    catch_response=True) as response:

                if response.status_code in [200, 204]:
                    log.warning(f"Path traversal in DELETE may be successful: {payload}")

    @task
    def test_directory_traversal_in_providers(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test path traversal in identity provider endpoints
        traversal_payloads = [
            "../../../config/database.xml",
            "..\\..\\..\\config\\application.properties",
            "/etc/shadow",
            "/proc/version",
            "/var/log/auth.log",
            "C:\\Windows\\System32\\config\\SAM"
        ]

        for payload in traversal_payloads:
            # Encode the payload for URL
            encoded_payload = payload.replace("/", "%2f").replace("\\", "%5c")

            with self.client.get(f"/api/v3/local-identity-providers/{encoded_payload}/accounts",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200 and any(keyword in response.text.lower()
                                                       for keyword in ["password", "root", "admin", "config"]):
                    log.critical(f"CRITICAL: Directory traversal successful: {payload}")
                    response.success()
                else:
                    log.info(f"Directory traversal blocked: {response.status_code}")

    @task
    def test_null_byte_injection(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Null byte injection payloads
        null_byte_payloads = [
            "legitimate_id%00../../etc/passwd",
            "valid_id\x00../../../etc/passwd",
            "test%00.txt",
            "admin%00.php",
            "config%00.xml"
        ]

        for payload in null_byte_payloads:
            with self.client.get(f"/api/v3/raw-credentials/{payload}",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"Null byte injection may be successful: {payload}")
                    response.success()
                else:
                    log.info(f"Null byte injection blocked: {response.status_code}")

    @task
    def test_unicode_encoding_bypass(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Unicode encoding bypass attempts
        unicode_payloads = [
            "%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
            "\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd",
            "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd",
            "\uFF0E\uFF0E\uFF0F\uFF0E\uFF0E\uFF0F\uFF0E\uFF0E\uFF0Fetc\uFF0Fpasswd"
        ]

        for payload in unicode_payloads:
            with self.client.get(f"/api/v3/raw-credentials/{payload}",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"Unicode encoding bypass may be successful: {payload}")
                    response.success()
                else:
                    log.info(f"Unicode encoding bypass blocked: {response.status_code}")


class PathTraversalUser(HttpUser):
    wait_time = constant(1)
    tasks = [PathTraversalAttacks]
