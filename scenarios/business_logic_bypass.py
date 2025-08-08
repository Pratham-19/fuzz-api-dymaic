import json
import logging
import time
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class BusinessLogicFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]
        self.created_credentials = []
        self.created_accounts = []

    @task
    def fuzz_duplicate_resource_creation(self):
        """Test creation of duplicate resources"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to create multiple credentials with same name
        credential_name = f"duplicate_test_{uuid.uuid4()}"

        credential_data = {
            "name": credential_name,
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        # Create first credential
        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              json=credential_data,
                              verify=False,
                              catch_response=True) as response:

            if response.status_code in [200, 201]:
                log.info("First credential created successfully")
                response.success()
                try:
                    cred_id = response.json().get("id")
                    if cred_id:
                        self.created_credentials.append(cred_id)
                except:
                    pass
            else:
                response.success()

        # Try to create duplicate
        with self.client.post("/api/v3/raw-credentials",
                              headers=headers,
                              json=credential_data,
                              verify=False,
                              catch_response=True) as response:

            if response.status_code in [400, 409, 422]:  # 409 = Conflict
                response.success()
                log.info("Duplicate creation properly blocked")
            elif response.status_code in [200, 201]:
                log.warning("Duplicate credential creation allowed!")
                response.success()
            else:
                response.success()

    @task
    def fuzz_sequential_operation_bypass(self):
        """Test bypassing sequential operation requirements"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Create credential and immediately try to use/modify it
        credential_data = {
            "name": f"sequential_test_{uuid.uuid4()}",
            "username": "testuser",
            "password": "testpass",
            "type": "OS"
        }

        # Create credential
        create_response = self.client.post("/api/v3/raw-credentials",
                                           headers=headers,
                                           json=credential_data,
                                           verify=False,
                                           catch_response=True)

        if create_response.status_code in [200, 201]:
            try:
                cred_id = create_response.json().get("id")
                if cred_id:
                    # Immediately try to update without delay
                    update_data = credential_data.copy()
                    update_data["password"] = "newpass"

                    with self.client.put(f"/api/v3/raw-credentials/{cred_id}",
                                         headers=headers,
                                         json=update_data,
                                         verify=False,
                                         catch_response=True) as response:

                        if response.status_code == 200:
                            log.info("Immediate update allowed")
                            response.success()
                        elif response.status_code in [400, 409]:
                            log.info("Immediate update blocked - sequential logic working")
                            response.success()
                        else:
                            response.success()

                    # Try to delete immediately
                    with self.client.delete(f"/api/v3/raw-credentials/{cred_id}",
                                            headers=headers,
                                            verify=False,
                                            catch_response=True) as response:

                        if response.status_code in [200, 204]:
                            log.info("Immediate deletion allowed")
                            response.success()
                        elif response.status_code in [400, 409]:
                            log.info("Immediate deletion blocked")
                            response.success()
                        else:
                            response.success()
            except:
                pass

    @task
    def fuzz_resource_limit_bypass(self):
        """Test bypassing resource creation limits"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to create many resources quickly
        creation_attempts = 20
        successful_creations = 0

        for i in range(creation_attempts):
            credential_data = {
                "name": f"limit_test_{i}_{uuid.uuid4()}",
                "username": f"user_{i}",
                "password": "testpass",
                "type": "OS"
            }

            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=credential_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [200, 201]:
                    successful_creations += 1
                    response.success()
                elif response.status_code in [400, 429]:  # Rate limited
                    log.info(f"Resource limit hit after {successful_creations} creations")
                    response.success()
                    break
                else:
                    response.success()

        log.info(f"Successfully created {successful_creations} resources")

    @task
    def fuzz_state_manipulation(self):
        """Test manipulation of resource state"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test account state manipulation
        account_data = {
            "name": f"state_test_{uuid.uuid4()}",
            "firstName": "Test",
            "lastName": "User",
            "emailAddress": "test@example.com",
            "enabled": True
        }

        # Create account
        create_response = self.client.post("/api/v3/local-identity-providers/default/accounts",
                                           headers=headers,
                                           json=account_data,
                                           verify=False,
                                           catch_response=True)

        if create_response.status_code in [200, 201]:
            try:
                account_locator = create_response.json().get("locator")
                if account_locator:
                    # Try to manipulate state fields
                    state_manipulations = [
                        {"enabled": False},  # Disable account
                        {"enabled": True},   # Re-enable account
                        {"enabled": "invalid"},  # Invalid state
                        {"internal": True},  # Try to set internal flag
                    ]

                    for manipulation in state_manipulations:
                        update_data = account_data.copy()
                        update_data.update(manipulation)

                        # Assuming there's an update endpoint for accounts
                        with self.client.put(f"/api/v3/local-identity-providers/default/accounts/{account_locator}",
                                             headers=headers,
                                             json=update_data,
                                             verify=False,
                                             catch_response=True) as response:

                            if response.status_code == 200:
                                log.info(f"State manipulation successful: {manipulation}")
                                response.success()
                            elif response.status_code in [400, 403, 422]:
                                log.info(f"State manipulation blocked: {manipulation}")
                                response.success()
                            else:
                                response.success()
            except:
                pass

    @task
    def fuzz_workflow_bypass(self):
        """Test bypassing intended workflow"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test accessing resources before proper initialization
        test_scenarios = [
            # Try to update non-existent credential
            {
                "method": "PUT",
                "endpoint": f"/api/v3/raw-credentials/{uuid.uuid4()}",
                "data": {"name": "test", "username": "user", "password": "pass", "type": "OS"}
            },

            # Try to delete non-existent credential
            {
                "method": "DELETE",
                "endpoint": f"/api/v3/raw-credentials/{uuid.uuid4()}",
                "data": None
            },

            # Try to get non-existent credential
            {
                "method": "GET",
                "endpoint": f"/api/v3/raw-credentials/{uuid.uuid4()}",
                "data": None
            },
        ]

        for scenario in test_scenarios:
            method = scenario["method"]
            endpoint = scenario["endpoint"]
            data = scenario["data"]

            with self.client.request(method,
                                     endpoint,
                                     headers=headers,
                                     json=data,
                                     verify=False,
                                     catch_response=True) as response:

                if response.status_code == 404:
                    log.info(f"Workflow bypass properly blocked: {method} {endpoint}")
                    response.success()
                elif response.status_code == 200:
                    log.warning(f"Workflow bypass successful: {method} {endpoint}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_privilege_escalation_logic(self):
        """Test business logic privilege escalation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Try to create resources with elevated privileges
        privilege_tests = [
            # Try to set internal flag
            {
                "name": "privilege_test",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "internal": True
            },

            # Try to specify custom ID
            {
                "name": "custom_id_test",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "id": "custom-admin-id"
            },

            # Try to set created by user
            {
                "name": "created_by_test",
                "username": "testuser",
                "password": "testpass",
                "type": "OS",
                "createdByUser": {"id": "admin-user", "owner": "administrator"}
            },
        ]

        for test_data in privilege_tests:
            with self.client.post("/api/v3/raw-credentials",
                                  headers=headers,
                                  json=test_data,
                                  verify=False,
                                  catch_response=True) as response:

                if response.status_code in [400, 403, 422]:
                    log.info(f"Privilege escalation blocked: {test_data.get('name')}")
                    response.success()
                elif response.status_code in [200, 201]:
                    log.warning(f"Privilege escalation successful: {test_data.get('name')}")
                    response.success()
                else:
                    response.success()

    @task
    def fuzz_timing_attack_logic(self):
        """Test timing-based business logic attacks"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test rapid operations that might bypass timing controls
        timing_tests = [
            # Rapid credential creations
            lambda: self.client.post("/api/v3/raw-credentials",
                                     headers=headers,
                                     json={"name": f"timing_{uuid.uuid4()}", "username": "user", "password": "pass", "type": "OS"},
                                     verify=False, catch_response=True),

            # Rapid account creations
            lambda: self.client.post("/api/v3/local-identity-providers/default/accounts",
                                     headers=headers,
                                     json={"name": f"timing_{uuid.uuid4()}", "firstName": "Test", "lastName": "User", "emailAddress": "test@example.com"},
                                     verify=False, catch_response=True),
        ]

        for test_func in timing_tests:
            # Perform rapid operations
            responses = []
            start_time = time.time()

            for i in range(5):
                response = test_func()
                responses.append(response.status_code)
                time.sleep(0.01)  # Very short delay

            end_time = time.time()

            success_count = sum(1 for status in responses if status in [200, 201])
            log.info(f"Timing test: {success_count}/5 successful in {end_time - start_time:.2f}s")

class BusinessLogicUser(HttpUser):
    wait_time = constant(1)
    tasks = [BusinessLogicFuzz]
    host = "https://localhost:8443"
