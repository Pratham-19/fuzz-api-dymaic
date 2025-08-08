import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/credential_injection_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class CredentialInjectionAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        CredentialInjectionAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        CredentialInjectionAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = CredentialInjectionAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = CredentialInjectionAttacks.json.payload(api_call="on_start")
        version = CredentialInjectionAttacks.json.version(api_call="on_start")
        uri = CredentialInjectionAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_credential_sql_injection(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # SQL Injection payloads for credential creation
        injection_payloads = [
            {"name": "test'; DROP TABLE credentials; --", "username": "admin", "password": "password", "type": "OS"},
            {"name": "test", "username": "admin' OR '1'='1", "password": "password", "type": "OS"},
            {"name": "test", "username": "admin", "password": "'; UNION SELECT * FROM users; --", "type": "OS"},
            {"name": "test/**/UNION/**/SELECT", "username": "admin", "password": "password", "type": "OS"},
            {"name": "test", "username": "admin'; INSERT INTO credentials VALUES('hacked'); --", "password": "password", "type": "OS"}
        ]

        for payload in injection_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Potential SQL Injection vulnerability detected: {payload}")
                    response.success()
                else:
                    log.info(f"SQL Injection attempt blocked: {response.status_code}")
                    response.failure(f"Injection blocked: {response.content}")

    @task
    def test_credential_xss_injection(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # XSS payloads for credential fields
        xss_payloads = [
            {"name": "<script>alert('XSS')</script>", "username": "admin", "password": "password", "type": "OS"},
            {"name": "test", "username": "<img src=x onerror=alert('XSS')>", "password": "password", "type": "OS"},
            {"name": "test", "username": "admin", "password": "javascript:alert('XSS')", "type": "OS"},
            {"name": "test\"><script>document.location='http://evil.com'</script>", "username": "admin", "password": "password", "type": "OS"}
        ]

        for payload in xss_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Potential XSS vulnerability detected: {payload}")
                    response.success()
                else:
                    log.info(f"XSS attempt blocked: {response.status_code}")


class CredentialInjectionUser(HttpUser):
    wait_time = constant(1)
    tasks = [CredentialInjectionAttacks]
