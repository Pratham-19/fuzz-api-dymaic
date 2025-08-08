import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/auth_bypass_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class AuthBypassAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        AuthBypassAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        AuthBypassAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = AuthBypassAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        # Skip authentication for bypass testing
        pass

    @task
    def test_no_auth_header(self):
        # Test accessing protected endpoints without authorization
        endpoints = [
            "/api/v3/raw-credentials",
            "/api/v3/active-directory-identity-providers",
            "/api/v3/local-identity-providers/default/accounts"
        ]

        for endpoint in endpoints:
            with self.client.get(endpoint,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.critical(f"CRITICAL: Accessed {endpoint} without authentication!")
                    response.success()
                else:
                    log.info(f"Access denied to {endpoint} without auth: {response.status_code}")

    @task
    def test_invalid_token_formats(self):
        # Test various invalid token formats
        invalid_tokens = [
            "Bearer invalid_token",
            "Bearer ",
            "Bearer null",
            "Bearer undefined",
            "Bearer ../../../etc/passwd",
            "Bearer <script>alert('xss')</script>",
            "Bearer " + "A" * 10000,  # Extremely long token
            "Basic YWRtaW46cGFzc3dvcmQ=",  # Wrong auth type
            "Token invalid",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid"
        ]

        for token in invalid_tokens:
            headers = {"Authorization": token}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.critical(f"CRITICAL: Invalid token accepted: {token}")
                    response.success()
                else:
                    log.info(f"Invalid token rejected: {response.status_code}")

    @task
    def test_jwt_manipulation(self):
        # Test JWT token manipulation attacks
        manipulated_tokens = [
            "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJ0cnVlIn0.",  # None algorithm
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImF1dGgiOiJ0cnVlIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid",  # Modified payload
            "Bearer " + "." * 100,  # Malformed JWT
        ]

        for token in manipulated_tokens:
            headers = {"Authorization": token}

            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.critical(f"CRITICAL: Manipulated JWT accepted: {token}")
                    response.success()
                else:
                    log.info(f"Manipulated JWT rejected: {response.status_code}")

    @task
    def test_header_injection(self):
        # Test HTTP header injection attacks
        malicious_headers = [
            {"Authorization": "Bearer valid\r\nX-Admin: true"},
            {"Authorization": "Bearer valid\nSet-Cookie: admin=true"},
            {"X-Original-URL": "/api/v3/raw-credentials"},
            {"X-Rewrite-URL": "/api/v3/raw-credentials"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"}
        ]

        for headers in malicious_headers:
            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.critical(f"CRITICAL: Header injection successful: {headers}")
                    response.success()
                else:
                    log.info(f"Header injection blocked: {response.status_code}")


class AuthBypassUser(HttpUser):
    wait_time = constant(1)
    tasks = [AuthBypassAttacks]
