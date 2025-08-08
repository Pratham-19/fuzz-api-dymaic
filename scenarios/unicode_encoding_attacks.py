import json
import logging
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class UnicodeEncodingFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_unicode_normalization_attacks(self):
        """Test Unicode normalization vulnerabilities"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Unicode normalization attacks
        unicode_payloads = [
            "admin",  # Normal
            "admin",  # Different Unicode composition
            "a\u0064min",  # 'd' as Unicode
            "ad\u006Din",  # 'm' as Unicode
            "adm\u0131n",  # Dotless i (Turkish)
            "аdmin",  # Cyrillic 'а' instead of Latin 'a'
            "admin\u200B",  # Zero-width space
            "admin\uFEFF",  # Byte order mark
            "admin\u202E",  # Right-to-left override
            "\u202Eadmin",  # RTL at beginning
        ]

        for payload in unicode_payloads:
            credential_data = {
                "name": f"unicode_test_{payload}",
                "username": payload,
                "password": "testpass",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    response.success()
                    log.info(f"Unicode payload accepted: {repr(payload)}")
                elif response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Unicode payload rejected: {repr(payload)}")
                else:
                    response.success()

    @task
    def fuzz_encoding_bypass_attacks(self):
        """Test encoding bypass techniques"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # URL encoding bypasses
        encoding_payloads = [
            "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
            "%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E",  # <script>alert('xss')</script>
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",  # ../../etc/passwd
            "%00admin",  # Null byte injection
            "admin%0D%0A",  # CRLF injection
            "%E2%80%8Badmin",  # Zero width space
            "%EF%BB%BFadmin",  # BOM
            "%C0%AE%C0%AE%C0%AF",  # Overlong UTF-8 ../
        ]

        for payload in encoding_payloads:
            credential_data = {
                "name": f"encoding_test",
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
                    log.info(f"Encoding bypass blocked: {payload}")
                elif response.status_code == 200:
                    log.warning(f"Potential encoding bypass: {payload}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_control_character_injection(self):
        """Test control character injection"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Control characters
        control_chars = [
            "admin\x00",  # Null
            "admin\x08",  # Backspace
            "admin\x09",  # Tab
            "admin\x0A",  # Line feed
            "admin\x0D",  # Carriage return
            "admin\x1B",  # Escape
            "admin\x7F",  # Delete
            "\x01admin",  # SOH at start
            "ad\x00min",  # Null in middle
        ]

        for char_payload in control_chars:
            account_data = {
                "name": char_payload,
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": "test@example.com"
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Control character blocked: {repr(char_payload)}")
                elif response.status_code == 200:
                    log.warning(f"Control character accepted: {repr(char_payload)}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_homograph_attacks(self):
        """Test homograph/lookalike character attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Homograph characters that look like Latin letters
        homograph_payloads = [
            "аdmin",  # Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
            "аdmіn",  # Cyrillic 'а' and 'і'
            "o̊dmin",  # 'o' with ring above
            "аdmın",  # Cyrillic 'а' and dotless i
            "gοοgle",  # Greek omicron instead of 'o'
            "miсrosoft",  # Cyrillic 'с' instead of 'c'
            "аррӏе",  # Mix of Cyrillic characters resembling "apple"
            "раypаl",  # Cyrillic characters resembling "paypal"
        ]

        for payload in homograph_payloads:
            credential_data = {
                "name": f"homograph_test",
                "username": payload,
                "password": "testpass",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    response.success()
                    log.info(f"Homograph username accepted: {payload}")
                elif response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Homograph username rejected: {payload}")
                else:
                    response.success()

    @task
    def fuzz_emoji_and_symbols(self):
        """Test emoji and symbol injection"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Emoji and symbols
        emoji_payloads = [
            "admin🎉",
            "😀user",
            "test💀",
            "admin⚠️",
            "user🔥password",
            "💻admin💻",
            "🚫test🚫",
            "admin⭐user",
            "🔐secure🔐",
            "admin®️"
        ]

        for payload in emoji_payloads:
            account_data = {
                "name": payload,
                "firstName": "Test",
                "lastName": "User",
                "emailAddress": "test@example.com"
            }

            with self.client.post("/api/v3/local-identity-providers/default/accounts",
                                  headers=headers,
                                  json=account_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    response.success()
                    log.info(f"Emoji payload accepted: {payload}")
                elif response.status_code in [400, 422]:
                    response.success()
                    log.info(f"Emoji payload rejected: {payload}")
                else:
                    response.success()

    @task
    def fuzz_bidi_override_attacks(self):
        """Test bidirectional text override attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # BiDi override attacks
        bidi_payloads = [
            "admin\u202Euser",  # RLO - right-to-left override
            "\u202Dadmin\u202C",  # LRO with pop
            "user\u061Cadmin",  # Arabic letter mark
            "test\u200Eadmin",  # Left-to-right mark
            "admin\u200Ftest",  # Right-to-left mark
            "\u2066admin\u2069",  # Left-to-right isolate
            "\u2067admin\u2069",  # Right-to-left isolate
        ]

        for payload in bidi_payloads:
            credential_data = {
                "name": f"bidi_test",
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
                    log.info(f"BiDi attack blocked: {repr(payload)}")
                elif response.status_code == 200:
                    log.warning(f"BiDi attack accepted: {repr(payload)}")
                    response.success()
                else:
                    response.success()

class UnicodeEncodingUser(HttpUser):
    wait_time = constant(1)
    tasks = [UnicodeEncodingFuzz]
    host = "https://localhost:8443"
