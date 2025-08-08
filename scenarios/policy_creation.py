
import os, csv
import pdb
import re
import sys
import json
import random
import logging
import uuid
from locust import HttpUser, task, User, HttpLocust, SequentialTaskSet, constant, events, env
stat_file = open('/tmp/success_req_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class CreateProtectionPolicyV3(SequentialTaskSet):
    json = None
    stat_file = None
    request_success_stats = [list()]
    request_fail_stats = [list()]

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        CreateProtectionPolicyV3.json = JsonConfig(args.json)

    def ingest_random(testfunc):
        def collect_fuzzy_data(self, *args):
            fuzzy_data = CreateProtectionPolicyV3.json.collect_similar_methods(method_name=f"{testfunc.__name__}")
            for random_data in fuzzy_data:
                testfunc(self, random_data[0]['api_call'])

        return collect_fuzzy_data

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        CreateProtectionPolicyV3.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            log.info(f"The response was {response.text}")
            log.info(f"The response was {response_time}")
            filename = CreateProtectionPolicyV3.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    @events.request_failure.add_listener
    def my_request_failure(request_type, name, response_time, response_length, **kw):
        stat_file.write(request_type + ";" + name + ";" + str(response_time) + ";" + str(response_length) + "\n")

    @events.quitting.add_listener
    def hook_quitting(environment, **kw):
        stat_file.close()

    def on_start(self):
        payload = CreateProtectionPolicyV3.json.payload(api_call="on_start")
        version = CreateProtectionPolicyV3.json.version(api_call="on_start")
        uri = CreateProtectionPolicyV3.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        #self.protection_policy_prereqConfig()
        return self.token

    def protection_policy_prereqConfig(self):
        # Before creating protection policy create storage unit name Production_Redy_Test_storage_unit manually
        # getting created StorageUnit
        headers = {"access_token": f"{self.token}"}
        version = CreateProtectionPolicyV3.json.version(api_call="get_storage_unit_id")
        response_status = CreateProtectionPolicyV3.json.response(api_call="get_storage_unit_id")
        uri = CreateProtectionPolicyV3.json.uri(api_call="get_storage_unit_id")
        get_response = self.client.get(uri.format(version),
                                       headers=headers,
                                       verify=False,
                                       catch_response=True)
        self.storage_unitId = json.loads(get_response.content)["content"][0]["id"]

    @task
    @ingest_random
    def post_plc_newstunit_v3(self, api):
        # Creating Protection policy
        headers = {"access_token": f"{self.token}"}
        version = CreateProtectionPolicyV3.json.version(api_call=api)
        response_status = CreateProtectionPolicyV3.json.response(api_call=api)
        uri = CreateProtectionPolicyV3.json.uri(api_call=api)
        payload = CreateProtectionPolicyV3.json.payload(api_call=api)

        opid = str(uuid.uuid4())
        upstreamid = str(uuid.uuid4())
        if payload["objectives"][0]['id'] is " ":
            payload["objectives"][0]['id'] = upstreamid
        if payload["objectives"][0]['operations'][0]['id'] is " ":
            payload["objectives"][0]['operations'][0]['id'] = opid
        if payload["objectives"][0]["target"]["storageTargetId"] is " ":
            payload["objectives"][0]["target"]["storageTargetId"] = str(uuid.uuid4())
        if payload["objectives"][0]["target"]["storageContainerId"] is " ":
            pstorage = CreateProtectionPolicyV3.json.get_value(api_call=api, key="primary_storage")

            get_pstorage_uri = ":8443/api/v2/storage-systems?filter=type eq \"DATA_DOMAIN_SYSTEM\" and name eq \"{}\"".format(pstorage)
            get_response = self.client.get(get_pstorage_uri,
                                           headers=headers,
                                           verify=False,
                                           catch_response=True)

            pstorage_uri = json.loads(get_response.content)["content"][0]["id"]


            payload["objectives"][0]["target"]["storageContainerId"] = pstorage_uri

        if payload["objectives"][0]["retentions"][0]["id"] is " ":
            payload["objectives"][0]["retentions"][0]["id"]=str(uuid.uuid4())
        if payload["objectives"][0]["retentions"][0]["copySelector"]["operationId"] is " ":
            payload["objectives"][0]["retentions"][0]["copySelector"]["operationId"]=opid
        if payload["objectives"][0]["retentions"][1]["id"] is " ":
            payload["objectives"][0]["retentions"][1]["id"]=str(uuid.uuid4())

        payload1 = json.dumps(payload)
        payload2 = json.loads(payload1)

        with self.client.post(uri.format(version),
                              headers=headers,
                              verify=False,
                              json=payload2,
                              catch_response=True) as response:

            if response.status_code == int(response_status):
                response.success()
                log.info(response.content)
                log.info(
                        f"post_plc_newstunit_v3 API status  >>> PASS == {api} ::: {response.request.body} ----> {response.content}")

            else:
                try:
                  if "The value of name field is not unique." in json.loads(response.content)['reason']:
                      log.info(response.content)
                      log.info(
                          f"post_plc_newstunit_v3 API status  >>> PASS == {api} ::: {response.request.body} ----> {response.content}")
                except:
                    log.info(response.content)
                    response.failure(
                        f"post_plc_newstunit_v3 >>> FAIL == {api} ::: {response.request.body} ----> {response.content}")
                    log.error(
                        f"post_plc_newstunit_v3 API status >>> FAIL == {api} ::: {response.request.body} ----> {response.content}")


class CreateProtectionPolicy_User(HttpUser):
    wait_time = constant(1)
    tasks = [CreateProtectionPolicyV3]
    request_success_stats = [list()]
    request_fail_stats = [list()]





    request_fail_stats = [list()]
