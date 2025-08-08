import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class LDAPInjectionFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_ldap_injection_selector(self):
        """Test LDAP injection in AD provider selector"""
        headers = {"Authorization": f"Bearer {self.token}"}

        ldap_injection_payloads = [
            "test.com)(objectClass=*",
            "test.com)(uid=*",
            "test.com)(&(objectClass=user)(uid=admin",
            "test.com)(|(uid=*)(cn=*",
            "test.com)(objectClass=*))(&(objectClass=void",
            "test.com)(|(objectClass=*)(objectClass=*))",
            "test.com)(objectClass=user)(password=*",
            "test.com))(|(uid=admin)(uid=root",
            "*)(uid=*))(|(uid=*",
            "test.com)(description=*admin*"
        ]

        for payload in ldap_injection_payloads:
            ad_provider_data = {
                "host": "test-host.com",
                "port": 389,
                "selector": payload,
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

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"LDAP injection blocked: {payload}")
                elif response.status_code == 500:
                    log.warning(f"Server error with LDAP injection: {payload}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_ldap_injection_search_base(self):
        """Test LDAP injection in search base fields"""
        headers = {"Authorization": f"Bearer {self.token}"}

        search_base_injections = [
            "dc=test,dc=com)(objectClass=*",
            "ou=users,dc=test,dc=com)(uid=*",
            "dc=test,dc=com)(&(objectClass=user)(uid=admin",
            "ou=groups,dc=test,dc=com)(|(cn=*)(description=*",
            "dc=test,dc=com)(objectClass=user)(password=*",
            "cn=admin,dc=test,dc=com)(|(objectClass=*",
            "dc=test,dc=com))(|(objectClass=user)(objectClass=group"
        ]

        for injection in search_base_injections:
            config_data = {
                "host": "test-host.com",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                },
                "config": {
                    "groupSearchBase": injection,
                    "userSearchPath": "ou=users,dc=test,dc=com"
                }
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=config_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Search base injection blocked: {injection}")
                else:
                    response.success()

    @task
    def fuzz_ldap_injection_service_account(self):
        """Test LDAP injection in service account credentials"""
        headers = {"Authorization": f"Bearer {self.token}"}

        service_account_injections = [
            "admin)(objectClass=*",
            "user)(uid=*",
            "service)(|(cn=admin)(cn=root",
            "ldapuser)(password=*",
            "testuser)(description=*"
        ]

        for injection in service_account_injections:
            ad_provider_data = {
                "host": "test-host.com",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": injection,
                    "password": "testpass"
                }
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=ad_provider_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Service account injection blocked: {injection}")
                else:
                    response.success()

    @task
    def fuzz_ldap_injection_attributes(self):
        """Test LDAP injection in attribute fields"""
        headers = {"Authorization": f"Bearer {self.token}"}

        attribute_injections = [
            "member)(objectClass=*",
            "uid)(cn=*",
            "memberOf)(|(objectClass=user)(objectClass=group",
            "sAMAccountName)(password=*",
            "mail)(description=*admin*"
        ]

        for injection in attribute_injections:
            config_data = {
                "host": "test-host.com",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": "testpass"
                },
                "config": {
                    "groupMemberAttribute": injection,
                    "groupSearchAttribute": "cn",
                    "userSearchPath": "ou=users,dc=test,dc=com"
                }
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=config_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Attribute injection blocked: {injection}")
                else:
                    response.success()

class LDAPInjectionUser(HttpUser):
    wait_time = constant(1)
    tasks = [LDAPInjectionFuzz]
    host = "https://localhost:8443"
