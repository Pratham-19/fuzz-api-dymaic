import os
import csv
import json
import logging
import uuid
import time
import threading
from locust import HttpUser, task, SequentialTaskSet, constant, events

stat_file = open('/tmp/rate_limit_bypass_stats.csv', 'w')
log = logging.getLogger(__name__)

for i in ['../../']:
    path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), i))
    if path not in sys.path:
        sys.path.insert(0, path)

from libs.jsonconfig.jsonconfig import JsonConfig


class RateLimitBypassAttacks(SequentialTaskSet):
    json = None
    stat_file = None

    @events.init_command_line_parser.add_listener
    def _collect_(parser):
        parser.add_argument("--stat_file", type=str, env_var="LOCUST_MY_ARGUMENT", default="", help="stat file name")
        parser.add_argument("--json", type=str, help="--json=<exact json path>. Not relative path like ~/")
        args = parser.parse_args()
        RateLimitBypassAttacks.json = JsonConfig(args.json)

    @events.test_start.add_listener
    def _(environment, **kw):
        log.info(f"Custom argument supplied: {environment.parsed_options.stat_file}")
        RateLimitBypassAttacks.stat_file = environment.parsed_options.stat_file

    @events.request.add_listener
    def my_request_handler(request_type, name, response_time, response_length, response,
                           exception, *args, **kwargs):
        if exception:
            log.info(f"Request to {name} failed with exception {exception}")
        else:
            log.info(f"Successfully made a request to: {name}")
            filename = RateLimitBypassAttacks.stat_file
            with open(filename, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([name, request_type, response_time, response_length])

    def on_start(self):
        payload = RateLimitBypassAttacks.json.payload(api_call="on_start")
        version = RateLimitBypassAttacks.json.version(api_call="on_start")
        uri = RateLimitBypassAttacks.json.uri(api_call="on_start")
        response = self.client.post(uri.format(version),
                                    json=payload,
                                    verify=False,
                                    catch_response=True)
        token_json = response.json()
        self.token = token_json["access_token"]
        log.debug("self.token={}".format(self.token))
        return self.token

    @task
    def test_ip_header_spoofing_bypass(self):
        # Test rate limit bypass using IP header spoofing
        ip_spoofing_headers = [
            {"Authorization": f"Bearer {self.token}", "X-Forwarded-For": "192.168.1.100"},
            {"Authorization": f"Bearer {self.token}", "X-Real-IP": "10.0.0.50"},
            {"Authorization": f"Bearer {self.token}", "X-Originating-IP": "172.16.0.25"},
            {"Authorization": f"Bearer {self.token}", "X-Forwarded": "for=203.0.113.195"},
            {"Authorization": f"Bearer {self.token}", "X-Cluster-Client-IP": "198.51.100.178"},
            {"Authorization": f"Bearer {self.token}", "CF-Connecting-IP": "8.8.8.8"},
            {"Authorization": f"Bearer {self.token}", "True-Client-IP": "1.1.1.1"},
            {"Authorization": f"Bearer {self.token}", "X-Client-IP": "9.9.9.9"}
        ]

        successful_requests = 0
        rate_limited_requests = 0

        for i, headers in enumerate(ip_spoofing_headers):
            payload = {
                "name": f"rate_limit_ip_test_{i}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    successful_requests += 1
                    log.info(f"Request successful with IP spoofing: {headers}")
                    response.success()
                elif response.status_code == 429:
                    rate_limited_requests += 1
                    log.info(f"Rate limited despite IP spoofing: {headers}")
                else:
                    log.info(f"Request failed: {response.status_code}")

        if successful_requests > rate_limited_requests:
            log.warning(f"IP spoofing may bypass rate limiting: {successful_requests}/{len(ip_spoofing_headers)} successful")

    @task
    def test_user_agent_rotation_bypass(self):
        # Test rate limit bypass using User-Agent rotation
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "curl/7.68.0",
            "PostmanRuntime/7.28.0",
            "python-requests/2.25.1",
            "Go-http-client/1.1",
            "Apache-HttpClient/4.5.13"
        ]

        successful_requests = 0

        for i, ua in enumerate(user_agents):
            headers = {
                "Authorization": f"Bearer {self.token}",
                "User-Agent": ua
            }

            payload = {
                "name": f"rate_limit_ua_test_{i}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    successful_requests += 1
                    response.success()
                elif response.status_code == 429:
                    log.info(f"Rate limited with User-Agent: {ua}")

        if successful_requests == len(user_agents):
            log.warning(f"User-Agent rotation may bypass rate limiting")

    @task
    def test_concurrent_request_bypass(self):
        # Test rate limit bypass using concurrent requests
        def make_concurrent_request(thread_id):
            headers = {"Authorization": f"Bearer {self.token}"}
            payload = {
                "name": f"concurrent_test_{thread_id}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            response = self.client.post("/api/v3/raw-credentials",
                                        headers=headers,
                                        verify=False,
                                        json=payload)

            return response.status_code

        # Launch multiple concurrent requests
        threads = []
        results = []

        for i in range(10):  # 10 concurrent requests
            thread = threading.Thread(target=lambda i=i: results.append(make_concurrent_request(i)))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        successful_concurrent = sum(1 for status in results if status in [200, 201])

        if successful_concurrent > 5:  # If more than half succeeded
            log.warning(f"Concurrent requests may bypass rate limiting: {successful_concurrent}/10 successful")

    @task
    def test_distributed_request_bypass(self):
        # Test rate limit bypass using distributed timing
        headers = {"Authorization": f"Bearer {self.token}"}

        # Make requests with slight delays to avoid burst detection
        request_intervals = [0.1, 0.2, 0.5, 1.0, 2.0]  # seconds
        successful_requests = 0

        for i, interval in enumerate(request_intervals):
            payload = {
                "name": f"distributed_test_{i}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    successful_requests += 1
                    response.success()
                elif response.status_code == 429:
                    log.info(f"Rate limited at interval {interval}s")

            time.sleep(interval)

        if successful_requests == len(request_intervals):
            log.warning(f"Distributed timing may bypass rate limiting")

    @task
    def test_session_rotation_bypass(self):
        # Test rate limit bypass using session rotation
        # Note: This would typically require multiple valid tokens
        headers = {"Authorization": f"Bearer {self.token}"}

        # Simulate session rotation by changing request characteristics
        session_variations = [
            {"Accept": "application/json"},
            {"Accept": "application/xml"},
            {"Accept": "*/*"},
            {"Accept-Language": "en-US,en;q=0.9"},
            {"Accept-Encoding": "gzip, deflate"},
        ]

        successful_requests = 0

        for i, variation in enumerate(session_variations):
            request_headers = {**headers, **variation}

            payload = {
                "name": f"session_rotation_test_{i}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=request_headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    successful_requests += 1
                    response.success()

        if successful_requests == len(session_variations):
            log.warning(f"Session rotation may bypass rate limiting")

    @task
    def test_rate_limit_discovery(self):
        # Discover rate limit thresholds
        headers = {"Authorization": f"Bearer {self.token}"}

        request_count = 0
        rate_limited = False

        while request_count < 50 and not rate_limited:  # Max 50 requests
            payload = {
                "name": f"rate_discovery_{request_count}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                request_count += 1

                if response.status_code == 429:
                    log.info(f"Rate limit triggered after {request_count} requests")
                    rate_limited = True
                    response.success()
                elif response.status_code in [200, 201]:
                    response.success()
                else:
                    log.info(f"Request failed with status: {response.status_code}")
                    break

            time.sleep(0.1)  # Small delay between requests

        if not rate_limited:
            log.warning(f"No rate limiting detected after {request_count} requests")

    @task
    def test_http_method_bypass(self):
        # Test rate limit bypass using different HTTP methods
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try the same endpoint with different methods
        test_methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
        successful_methods = []

        for method in test_methods:
            payload = {
                "name": f"method_bypass_{method}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            if method == 'GET':
                response = self.client.get("/api/v3/raw-credentials",
                                           headers=headers,
                                           verify=False)
            elif method == 'POST':
                response = self.client.post("/api/v3/raw-credentials",
                                            headers=headers,
                                            verify=False,
                                            json=payload)
            elif method == 'PUT':
                response = self.client.put("/api/v3/raw-credentials/dummy_id",
                                           headers=headers,
                                           verify=False,
                                           json=payload)
            elif method == 'PATCH':
                response = self.client.patch("/api/v3/raw-credentials/dummy_id",
                                             headers=headers,
                                             verify=False,
                                             json=payload)
            elif method == 'DELETE':
                response = self.client.delete("/api/v3/raw-credentials/dummy_id",
                                              headers=headers,
                                              verify=False)

            if response.status_code not in [429, 405]:  # Not rate limited or method not allowed
                successful_methods.append(method)

        if len(successful_methods) > 1:
            log.warning(f"HTTP method variation may bypass rate limiting: {successful_methods}")

    @task
    def test_cache_bypass_headers(self):
        # Test rate limit bypass using cache-busting headers
        base_headers = {"Authorization": f"Bearer {self.token}"}

        cache_bypass_variations = [
            {"Cache-Control": "no-cache"},
            {"Pragma": "no-cache"},
            {"Cache-Control": "no-store"},
            {"If-None-Match": "*"},
            {"If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT"},
            {"X-Cache-Bypass": "true"},
            {"X-No-Cache": "true"}
        ]

        successful_requests = 0

        for i, cache_headers in enumerate(cache_bypass_variations):
            headers = {**base_headers, **cache_headers}

            payload = {
                "name": f"cache_bypass_{i}_{uuid.uuid4()}",
                "username": "admin",
                "password": "password",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  verify=False,
                                  json=payload,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    successful_requests += 1
                    response.success()

        if successful_requests == len(cache_bypass_variations):
            log.warning(f"Cache bypass headers may avoid rate limiting")


class RateLimitBypassUser(HttpUser):
    wait_time = constant(1)
    tasks = [RateLimitBypassAttacks]
