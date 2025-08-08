import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events
import sys

stat_file = open('/tmp/ldap_injection_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class LdapInjectionAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        LdapInjectionAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        LdapInjectionAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = LdapInjectionAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = LdapInjectionAttacks.json.payload(api_call="on_start")
        version = LdapInjectionAttacks.json.version(api_call="on_start")
        uri = LdapInjectionAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_ldap_injection_in_ad_provider(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # LDAP injection payloads for Active Directory provider creation
        ldap_injection_payloads = [
            {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "example.com)(|(objectClass=*",  # Break out of filter
                "secure": False,
                "description": "LDAP Injection Test",
                "serviceAccount": {
                    "name": "admin)(&(objectClass=user)(memberOf=*",
                    "password": "password"
                },
                "config": {
                    "userSearchPath": "ou=users,dc=example,dc=com)(|(objectClass=*",
                    "groupSearchBase": "ou=groups,dc=example,dc=com",
                    "groupSearchAttribute": "member",
                    "groupMemberAttribute": "memberOf",
                    "userObjectTypeName": "user",
                    "groupObjectTypeName": "group"
                }
            },
            {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "example.com",
                "secure": False,
                "description": "LDAP Injection Test 2",
                "serviceAccount": {
                    "name": "*)(uid=*))(|(uid=*",
                    "password": "password"
                },
                "config": {
                    "userSearchPath": "ou=users,dc=example,dc=com",
                    "groupSearchBase": "ou=groups,dc=example,dc=com)(&(objectClass=*",
                    "groupSearchAttribute": "member",
                    "groupMemberAttribute": "memberOf",
                    "userObjectTypeName": "user",
                    "groupObjectTypeName": "group"
                }
            },
            {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "*",  # Wildcard selector
                "secure": False,
                "description": "LDAP Injection Test 3",
                "serviceAccount": {
                    "name": "admin",
                    "password": "password"
                },
                "config": {
                    "userSearchPath": "*",
                    "groupSearchBase": "*",
                    "groupSearchAttribute": "*)(objectClass=*",
                    "groupMemberAttribute": "*",
                    "userObjectTypeName": "*",
                    "groupObjectTypeName": "*"
                }
            }
        ]

        for payload in ldap_injection_payloads:
            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"LDAP injection may be successful in AD provider")
                    response.success()
                else:
                    log.info(f"LDAP injection blocked in AD provider: {response.status_code}")

    @task
    def test_ldap_filter_bypass(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test LDAP filter bypass techniques
        filter_bypass_payloads = [
            "selector=*)(objectClass=*",
            "selector=*)(&(objectClass=user)(cn=*",
            "selector=example.com)(&(|(objectClass=*)(objectClass=*",
            "selector=*))(%26(objectClass=user",
            "selector=example.com)(&(objectClass=*)(|(cn=*",
            "selector=*))(|(objectClass=*))((objectClass=*",
            "selector=example.com)(|(objectClass=*)(objectClass=group",
        ]

        for bypass_payload in filter_bypass_payloads:
            # Use as query parameter
            with self.client.get(f"/api/v3/active-directory-identity-providers?{bypass_payload}",
                                 headers=headers,
                                 verify=False,
                                 catch_response=True) as response:

                if response.status_code == 200:
                    log.warning(f"LDAP filter bypass may be successful: {bypass_payload}")
                    response.success()
                else:
                    log.info(f"LDAP filter bypass blocked: {response.status_code}")

    @task
    def test_ldap_blind_injection(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Blind LDAP injection payloads
        blind_injection_payloads = [
            {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "example.com",
                "secure": False,
                "description": "Test",
                "serviceAccount": {
                    "name": "admin)(cn=a*",
                    "password": "password"
                }
            },
            {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "example.com",
                "secure": False,
                "description": "Test",
                "serviceAccount": {
                    "name": "admin)(cn=b*",
                    "password": "password"
                }
            },
            {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "example.com",
                "secure": False,
                "description": "Test",
                "serviceAccount": {
                    "name": "admin)(objectClass=user)(cn=admin*",
                    "password": "password"
                }
            }
        ]

        response_times = []
        for payload in blind_injection_payloads:
            import time
            start_time = time.time()

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                end_time = time.time()
                response_time = end_time - start_time
                response_times.append(response_time)

                if response.status_code in [200, 201]:
                    log.warning(f"Blind LDAP injection response: {response_time}s")
                    response.success()

        # Analyze response times for timing-based blind injection
        if len(response_times) > 1:
            avg_time = sum(response_times) / len(response_times)
            for i, time_val in enumerate(response_times):
                if time_val > avg_time * 2:  # Significantly longer response
                    log.warning(f"Potential timing-based blind LDAP injection detected at payload {i}")

    @task
    def test_ldap_attribute_injection(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test injection in LDAP attribute fields
        attribute_injection_payload = {
            "host": "ldap.example.com",
            "port": 389,
            "selector": "example.com",
            "secure": False,
            "description": "Attribute Injection Test",
            "serviceAccount": {
                "name": "admin",
                "password": "password"
            },
            "config": {
                "userSearchPath": "ou=users,dc=example,dc=com",
                "groupSearchBase": "ou=groups,dc=example,dc=com",
                "groupSearchAttribute": "member)(objectClass=*",
                "groupMemberAttribute": "memberOf)(|(objectClass=*",
                "userObjectTypeName": "user)(objectClass=*",
                "groupObjectTypeName": "group)(objectClass=*"
            }
        }

        with self.client.post("/api/v3/active-directory-identity-providers",
                              headers=headers,
                              verify=False,
                              json=attribute_injection_payload,
                              catch_response=True) as response:

            if response.status_code in [200, 201]:
                log.warning(f"LDAP attribute injection may be successful")
                response.success()
            else:
                log.info(f"LDAP attribute injection blocked: {response.status_code}")

    @task
    def test_ldap_dn_injection(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test DN (Distinguished Name) injection
        dn_injection_payloads = [
            "cn=admin,ou=users,dc=example,dc=com)(objectClass=*",
            "cn=admin,ou=users,dc=example,dc=com)(&(objectClass=user)(cn=*",
            "cn=*,ou=*,dc=*,dc=*",
            "cn=admin)(objectClass=user)(memberOf=cn=admins,ou=groups,dc=example,dc=com",
            "cn=admin,ou=users,dc=example,dc=com))(|(objectClass=*"
        ]

        for dn_payload in dn_injection_payloads:
            payload = {
                "host": "ldap.example.com",
                "port": 389,
                "selector": "example.com",
                "secure": False,
                "description": "DN Injection Test",
                "serviceAccount": {
                    "name": dn_payload,
                    "password": "password"
                },
                "config": {
                    "userSearchPath": dn_payload,
                    "groupSearchBase": "ou=groups,dc=example,dc=com",
                    "groupSearchAttribute": "member",
                    "groupMemberAttribute": "memberOf",
                    "userObjectTypeName": "user",
                    "groupObjectTypeName": "group"
                }
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"LDAP DN injection may be successful: {dn_payload}")
                    response.success()
                else:
                    log.info(f"LDAP DN injection blocked: {response.status_code}")


class LdapInjectionUser(HttpUser):
    wait_time = constant(1)
    tasks = [LdapInjectionAttacks]
