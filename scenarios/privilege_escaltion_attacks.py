import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/privilege_escalation_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class PrivilegeEscalationAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        PrivilegeEscalationAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        PrivilegeEscalationAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = PrivilegeEscalationAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = PrivilegeEscalationAttacks.json.payload(api_call="on_start")
        version = PrivilegeEscalationAttacks.json.version(api_call="on_start")
        uri = PrivilegeEscalationAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_admin_credential_creation(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Attempt to create admin-level credentials
        admin_payloads = [
            {"name": "system_admin", "username": "root", "password": "admin123", "type": "OS"},
            {"name": "domain_admin", "username": "administrator", "password": "admin123", "type": "POWERPROTECT"},
            {"name": "sa_account", "username": "sa", "password": "admin123", "type": "DBUSER"},
            {"name": "vcenter_admin", "username": "administrator@vsphere.local", "password": "admin123", "type": "VCENTER"},
            {"name": "k8s_admin", "username": "admin", "password": "admin123", "type": "KUBERNETES"},
        ]

        for payload in admin_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Admin credential creation allowed: {payload['name']}")
                    response.success()
                else:
                    log.info(f"Admin credential creation blocked: {response.status_code}")

    @task
    def test_credential_type_escalation(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test escalation through credential types
        escalation_types = [
            "SUPER_ADMIN",
            "SYSTEM",
            "ROOT",
            "ADMIN",
            "POWERPROTECT_ADMIN",
            "GLOBAL_ADMIN",
            "../ADMIN",
            "OS; DROP TABLE users; --",
            "POWERPROTECT\x00ADMIN"
        ]

        for cred_type in escalation_types:
            payload = {
                "name": f"test_{uuid.uuid4()}",
                "username": "testuser",
                "password": "testpass",
                "type": cred_type
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Credential type escalation may be possible: {cred_type}")
                    response.success()
                else:
                    log.info(f"Credential type escalation blocked: {response.status_code}")

    @task
    def test_internal_credential_manipulation(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to create internal credentials (should be system-only)
        internal_payloads = [
            {"name": "internal_sys", "username": "system", "password": "pass", "type": "OS", "internal": True},
            {"name": "service_account", "username": "service", "password": "pass", "type": "POWERPROTECT", "internal": True},
            {"name": "bootstrap_admin", "username": "admin", "password": "pass", "type": "OS", "internal": True}
        ]

        for payload in internal_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.critical(f"CRITICAL: Internal credential creation allowed: {payload['name']}")
                    response.success()
                else:
                    log.info(f"Internal credential creation blocked: {response.status_code}")

    @task
    def test_role_injection_via_extrainfo(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Attempt privilege escalation through extraInfo fields
        privilege_extrainfo = [
            [{"name": "role", "value": "admin"}],
            [{"name": "permissions", "value": "all"}],
            [{"name": "level", "value": "superuser"}],
            [{"name": "access", "value": "root"}],
            [{"name": "groups", "value": "administrators,domain_admins"}],
            [{"name": "sudo", "value": "ALL=(ALL) NOPASSWD:ALL"}],
            [{"name": "privilege", "value": "SeDebugPrivilege,SeBackupPrivilege"}]
        ]

        for extra_info in privilege_extrainfo:
            payload = {
                "name": f"test_{uuid.uuid4()}",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "extraInfo": extra_info
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Privilege escalation via extraInfo may be possible: {extra_info}")
                    response.success()
                else:
                    log.info(f"Privilege escalation via extraInfo blocked: {response.status_code}")

    @task
    def test_user_id_manipulation(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to manipulate user ownership
        user_manipulation_payloads = [
            {"name": "test", "username": "user", "password": "pass", "type": "OS",
             "createdByUser": {"id": "admin", "owner": "administrator"}},
            {"name": "test2", "username": "user", "password": "pass", "type": "OS",
             "createdByUser": {"id": "system", "owner": "SYSTEM"}},
            {"name": "test3", "username": "user", "password": "pass", "type": "OS",
             "createdByUser": {"id": "0", "owner": "root"}},
        ]

        for payload in user_manipulation_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"User ID manipulation may be possible")
                    response.success()
                else:
                    log.info(f"User ID manipulation blocked: {response.status_code}")

    @task
    def test_credential_hijacking(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # First, get existing credentials
        with self.client.get("/api/v3/raw-credentials",
                             headers=headers,
                             verify=False,
                             catch_response=True) as response:

            if response.status_code == 200:
                credentials = response.json()

                # Try to update existing credentials with admin privileges
                for cred in credentials[:3]:  # Test first 3 credentials
                    if 'id' in cred:
                        hijack_payload = {
                            "id": cred['id'],
                            "name": cred.get('name', 'hijacked'),
                            "username": "hijacked_admin",
                            "password": "hijacked_password",
                            "type": "POWERPROTECT",
                            "internal": True
                        }

                        with self.client.put(f"/api/v3/raw-credentials/{cred['id']}",
                                             headers=headers,
                                             verify=False,
                                             json=hijack_payload,
                                             catch_response=True) as update_response:

                            if update_response.status_code == 200:
                                log.critical(f"CRITICAL: Credential hijacking successful for ID: {cred['id']}")
                                update_response.success()
                            else:
                                log.info(f"Credential hijacking blocked: {update_response.status_code}")


class PrivilegeEscalationUser(HttpUser):
    wait_time = constant(1)
    tasks = [PrivilegeEscalationAttacks]
