import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/csrf_attacks_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class CsrfAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        CsrfAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        CsrfAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = CsrfAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = CsrfAttacks.json.payload(api_call="on_start")
        version = CsrfAttacks.json.version(api_call="on_start")
        uri = CsrfAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_csrf_without_origin_header(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        # Remove Origin and Referer headers to simulate CSRF

        payload = {
            "name": f"csrf_test_{uuid.uuid4()}",
            "username": "admin",
            "password": "password",
            "type": "OS"
        }

        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              verify=False,
                              json=payload,
                              catch_response=True) as response:

            if response.status_code in [200, 201]:
                log.warning(f"CSRF without Origin header successful")
                response.success()
            else:
                log.info(f"CSRF without Origin header blocked: {response.status_code}")

    @task
    def test_csrf_with_malicious_origin(self):
        # Test with malicious origin headers
        malicious_origins = [
            "http://evil.com",
            "https://attacker.com",
            "http://localhost:8443.evil.com",
            "https://evil.com:8443",
            "http://127.0.0.1:8443",
            "null",
            "data:text/html,<script>alert('xss')</script>",
            "javascript:alert('xss')"
        ]

        for origin in malicious_origins:
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Origin": origin,
                "Referer": origin
            }

            payload = {
                "name": f"csrf_origin_test_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"CSRF with malicious origin successful: {origin}")
                    response.success()
                else:
                    log.info(f"CSRF with malicious origin blocked: {response.status_code} for {origin}")

    @task
    def test_csrf_content_type_bypass(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Origin": "http://evil.com",
            "Content-Type": "text/plain"  # Try to bypass CORS preflight
        }

        payload = {
            "name": f"csrf_bypass_{uuid.uuid4()}",
            "username": "admin",
            "password": "password",
            "type": "OS"
        }

        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              verify=False,
                              json=payload,
                              catch_response=True) as response:

            if response.status_code in [200, 201]:
                log.warning(f"CSRF content-type bypass successful")
                response.success()
            else:
                log.info(f"CSRF content-type bypass blocked: {response.status_code}")

    @task
    def test_csrf_method_override(self):
        # Test HTTP method override techniques
        method_override_headers = [
            {"Authorization": f"Bearer {self.token}", "X-HTTP-Method-Override": "POST"},
            {"Authorization": f"Bearer {self.token}", "X-HTTP-Method": "POST"},
            {"Authorization": f"Bearer {self.token}", "X-Method-Override": "POST"},
            {"Authorization": f"Bearer {self.token}", "_method": "POST"}
        ]

        payload = {
            "name": f"csrf_method_override_{uuid.uuid4()}",
            "username": "admin",
            "password": "password",
            "type": "OS"
        }

        for headers in method_override_headers:
            # Try using GET with method override
            with self.client.get("/api/v3/raw-credentials",
                                 headers=headers,
                                 params=payload,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"CSRF method override successful")
                    response.success()
                else:
                    log.info(f"CSRF method override blocked: {response.status_code}")

    @task
    def test_csrf_form_encoded_bypass(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Origin": "http://evil.com",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Try form-encoded data (can be sent without preflight)
        form_data = f"name=csrf_form_{uuid.uuid4()}&username=admin&password=password&type=OS"

        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              verify=False,
                              data=form_data,
                              catch_response=True) as response:

            if response.status_code in [200, 201]:
                log.warning(f"CSRF form-encoded bypass successful")
                response.success()
            else:
                log.info(f"CSRF form-encoded bypass blocked: {response.status_code}")

    @task
    def test_csrf_subdomain_attack(self):
        # Test CSRF from subdomain (might be allowed by CORS)
        subdomain_origins = [
            "http://test.localhost:8443",
            "https://api.localhost:8443",
            "http://admin.localhost:8443",
            "https://evil.localhost:8443"
        ]

        for origin in subdomain_origins:
            headers = {
                "Authorization": f"Bearer {self.token}",
                "Origin": origin,
                "Referer": origin + "/evil_page"
            }

            payload = {
                "name": f"csrf_subdomain_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"CSRF subdomain attack successful: {origin}")
                    response.success()
                else:
                    log.info(f"CSRF subdomain attack blocked: {response.status_code} for {origin}")

    @task
    def test_csrf_json_with_callback(self):
        # Test JSONP-style CSRF
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Origin": "http://evil.com"
        }

        # Try callback parameter
        params = {
            "callback": "evil_function",
            "jsonp": "evil_callback"
        }

        payload = {
            "name": f"csrf_jsonp_{uuid.uuid4()}",
            "username": "admin",
            "password": "password",
            "type": "OS"
        }

        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              params=params,
                              verify=False,
                              json=payload,
                              catch_response=True) as response:

            if response.status_code in [200, 201]:
                log.warning(f"CSRF JSONP-style attack successful")
                response.success()
            else:
                log.info(f"CSRF JSONP-style attack blocked: {response.status_code}")

    @task
    def test_csrf_delete_operations(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # First create a credential to delete
        create_payload = {
            "name": f"csrf_delete_test_{uuid.uuid4()}",
            "username": "admin",
            "password": "password",
            "type": "OS"
        }

        create_response = self.client.post("/api/v3/raw-credentials",
                                           headers=headers,
                                           verify=False,
                                           json=create_payload)

        if create_response.status_code in [200, 201]:
            created_cred = create_response.json()
            cred_id = created_cred.get('id')

            if cred_id:
                # Now test CSRF on DELETE operation
                csrf_headers = {
                    "Authorization": f"Bearer {self.token}",
                    "Origin": "http://evil.com"
                }

                with self.client.delete(f"/api/v3/raw-credentials/{cred_id}",
                                        headers=csrf_headers,
                                        verify=False,
                                        catch_response=True) as response:

                    if response.status_code == 204:
                        log.critical(f"CRITICAL: CSRF DELETE operation successful")
                        response.success()
                    else:
                        log.info(f"CSRF DELETE operation blocked: {response.status_code}")


class CsrfAttacksUser(HttpUser):
    wait_time = constant(1)
    tasks = [CsrfAttacks]
