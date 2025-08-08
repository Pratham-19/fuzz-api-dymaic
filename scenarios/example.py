import os
import csv
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

log = logging.getLogger(__name__)
for i in ['../../']:
    p = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if p not in sys.path:
        sys.path.insert(0, p)
from libs.jsonconfig.jsonconfig import JsonConfig


class Protectionpolicy(SequentialTaskSet):
    json = None
    stat_file = None
    request_success_stats = [list()]
    request_fail_stats = [list()]

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        Protectionpolicy.json = JsonConfig(args.json)

    def ingest_random(testfunc):
        def collect_fuzzy_data(self, *args):
            fuzzy_data = Protectionpolicy.json.collect_similar_methods(method_name=f"{testfunc.__name__}")
            for random_data in fuzzy_data:
                testfunc(self, random_data[0]['api_call'])

        return collect_fuzzy_data

    @events.test_start.add_listener
    def _(environment, **kw):
        print(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        Protectionpolicy.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            log.info(f"The response was {response.text}")
            log.info(f"The response was {response_time}")
            filename = Protectionpolicy.stat_file
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
        payload = Protectionpolicy.json.payload(api_call="on_start")
        version = Protectionpolicy.json.version(api_call="on_start")
        uri = Protectionpolicy.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    @ingest_random
    def pp_manual_replication_selected_asset_v2(self, api):
        headers = {"access_token": f"{self.token}"}
        version = Protectionpolicy.json.version(api_call=api)
        response_status = Protectionpolicy.json.response(api_call=api)
        uri = Protectionpolicy.json.uri(api_call=api)
        payload = Protectionpolicy.json.payload(api_call=api)

        # get the policy id by name:
        pp_name = Protectionpolicy.json.get_value(api_call=api, key="plc_name")
        get_plc_uri = ":8443/api/v2/protection-policies?filter=name eq \"{}\"".format(pp_name)
        get_response = self.client.get(get_plc_uri,
                                       headers=headers,
                                       verify=False,
                                       catch_response=True)
        protection_policy_id = json.loads(get_response.content)["content"][0]["id"]

        # getting stageID
        headers = {"access_token": f"{self.token}"}
        get_plcstage_uri = ":8443/api/v3/protection-policies/{}".format(protection_policy_id)
        self.get_stageID_response = self.client.get(get_plcstage_uri,
                                                    headers=headers,
                                                    verify=False,
                                                    catch_response=True)

        # get asset_id
        asset_name = Protectionpolicy.json.get_value(api_call=api, key="asset_name1")
        asset_uri = ":8443/api/v2/assets?filter=name eq \"{}\"".format(asset_name)
        asset_response = self.client.get(asset_uri,
                                         headers=headers,
                                         verify=False,
                                         catch_response=True)
        asste_id = json.loads(asset_response.content)["content"][0]["id"]

        if payload["source"]["assetIds"][0] is " ":
            payload["source"]["assetIds"][0] = asste_id
        if payload["policy"]["id"] is " ":
            payload["policy"]["id"] = json.loads(self.get_stageID_response.content)["id"]
        if payload["policy"]["objectives"][0]["id"] is " ":
            payload["policy"]["objectives"][0]["id"] = json.loads(self.get_stageID_response.content)["objectives"][1]["id"]

        with self.client.post(uri.format(version),
                              headers=headers,
                              verify=False,
                              json=payload,
                              catch_response=True) as response:
            if response.status_code == int("202"):
                log.info(response.content)
                log.info(
                        f"pp_manual_replication_selected_asset_v2 API status  >>> PASS == {api} ::: {response.request.body} ----> {response.content}")
            else:
                log.info(response.content)
                response.failure(
                    f"pp_manual_replication_selected_asset_v2 >>> FAIL == {api} ::: {response.request.body} ----> {response.content}")
                log.error("pp_manual_replication_selected_asset_v2 API status code : {}".format(response.status_code))
                log.error(
                    f"pp_manual_replication_selected_asset_v2 API status >>> FAIL == {api} ::: {response.request.body} ----> {response.content}")


class Protectionpolicy_User(HttpUser):
    wait_time = constant(1)
    tasks = [Protectionpolicy]
    request_success_stats = [list()]
