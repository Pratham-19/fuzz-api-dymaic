import json
import logging
import threading
import time
import uuid
from locust import HttpUser, task, SequentialTaskSet, constant

log = logging.getLogger(__name__)

class RaceConditionFuzz(SequentialTaskSet):

    def on_start(self):
        """Get authentication token"""
        payload = {"username": "admin", "password": "admin123"}
        response = self.client.post("/api/v3/login", json=payload, verify=False, catch_response=True)
        self.token = "fake_token" if response.status_code != 200 else response.json()["access_token"]
        self.created_credentials = []
        self.created_accounts = []

    @task
    def fuzz_concurrent_credential_creation(self):
        """Test race conditions in credential creation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test creating multiple credentials with same name simultaneously
        credential_name = f"race_test_{uuid.uuid4()}"

        def create_credential():
            credential_data = {
                "name": credential_name,
                "username": f"user_{threading.current_thread().ident}",
                "password": "testpass",
                "type": "OS"
            }

            response = self.client.post("/api/v3/raw-credentials",
                                        headers=headers,
                                        json=credential_data,
                                        verify=False,
                                        catch_response=True)

            if response.status_code == 200:
                try:
                    cred_id = response.json().get("id")
                    if cred_id:
                        self.created_credentials.append(cred_id)
                except:
                    pass

            return response.status_code

        # Create multiple threads to test race condition
        threads = []
        results = []

        for i in range(5):
            thread = threading.Thread(target=lambda: results.append(create_credential()))
            threads.append(thread)

        # Start all threads at roughly the same time
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results
        success_count = sum(1 for status in results if status == 200)
        log.info(f"Race condition test: {success_count} credentials created successfully")

        # This should ideally return success as the test completed
        return True

    @task
    def fuzz_concurrent_account_creation(self):
        """Test race conditions in account creation"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test creating accounts with same email simultaneously
        email = f"race_test_{uuid.uuid4()}@example.com"

        def create_account():
            account_data = {
                "name": f"race_user_{threading.current_thread().ident}",
                "firstName": "Race",
                "lastName": "Test",
                "emailAddress": email
            }

            response = self.client.post("/api/v3/local-identity-providers/default/accounts",
                                        headers=headers,
                                        json=account_data,
                                        verify=False,
                                        catch_response=True)

            if response.status_code == 200:
                try:
                    account_id = response.json().get("locator")
                    if account_id:
                        self.created_accounts.append(account_id)
                except:
                    pass

            return response.status_code

        # Create multiple threads
        threads = []
        results = []

        for i in range(3):
            thread = threading.Thread(target=lambda: results.append(create_account()))
            threads.append(thread)

        # Start all threads simultaneously
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # Check for duplicate accounts
        success_count = sum(1 for status in results if status == 200)
        log.info(f"Account race condition test: {success_count} accounts created")

        return True

    @task
    def fuzz_rapid_crud_operations(self):
        """Test rapid CRUD operations for race conditions"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Create a credential
        credential_data = {
            "name": f"rapid_test_{uuid.uuid4()}",
            "username": "rapiduser",
            "password": "rapidpass",
            "type": "OS"
        }

        create_response = self.client.post("/api/v3/raw-credentials",
                                           headers=headers,
                                           json=credential_data,
                                           verify=False,
                                           catch_response=True)

        if create_response.status_code == 200:
            try:
                cred_id = create_response.json().get("id")
                if cred_id:
                    # Rapidly perform operations on the same credential
                    operations = []

                    def read_credential():
                        return self.client.get(f"/api/v3/raw-credentials/{cred_id}",
                                               headers=headers,
                                               verify=False,
                                               catch_response=True)

                    def update_credential():
                        update_data = credential_data.copy()
                        update_data["password"] = "newpass"
                        return self.client.put(f"/api/v3/raw-credentials/{cred_id}",
                                               headers=headers,
                                               json=update_data,
                                               verify=False,
                                               catch_response=True)

                    def delete_credential():
                        return self.client.delete(f"/api/v3/raw-credentials/{cred_id}",
                                                  headers=headers,
                                                  verify=False,
                                                  catch_response=True)

                    # Create threads for concurrent operations
                    threads = []
                    for i in range(10):
                        if i % 3 == 0:
                            thread = threading.Thread(target=read_credential)
                        elif i % 3 == 1:
                            thread = threading.Thread(target=update_credential)
                        else:
                            thread = threading.Thread(target=delete_credential)
                        threads.append(thread)

                    # Start all operations at once
                    for thread in threads:
                        thread.start()

                    for thread in threads:
                        thread.join()

                    log.info("Rapid CRUD operations completed")

            except Exception as e:
                log.error(f"Error in rapid CRUD test: {e}")

    @task
    def fuzz_session_hijacking_attempts(self):
        """Test session-related race conditions"""
        headers = {"Authorization": f"Bearer {self.token}"}

        def make_authenticated_request():
            return self.client.get("/api/v3/raw-credentials",
                                   headers=headers,
                                   verify=False,
                                   catch_response=True)

        def make_logout_request():
            return self.client.post("/api/v3/logout",
                                    headers=headers,
                                    verify=False,
                                    catch_response=True)

        # Test simultaneous authenticated requests and logout
        threads = []
        results = []

        # Multiple authenticated requests
        for i in range(5):
            thread = threading.Thread(target=lambda: results.append(make_authenticated_request().status_code))
            threads.append(thread)

        # One logout request
        thread = threading.Thread(target=lambda: results.append(make_logout_request().status_code))
        threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # Check if any requests succeeded after logout
        success_after_logout = sum(1 for status in results if status == 200)
        log.info(f"Session race condition test: {success_after_logout} successful requests")

    @task
    def fuzz_resource_exhaustion(self):
        """Test resource exhaustion through rapid requests"""
        headers = {"Authorization": f"Bearer {self.token}"}

        def rapid_request():
            # Make rapid requests to potentially exhaust resources
            for i in range(10):
                self.client.get("/api/v3/raw-credentials",
                                headers=headers,
                                params={"page": i, "pageSize": 100},
                                verify=False,
                                catch_response=True)
                time.sleep(0.01)  # Very short delay

        # Create multiple threads for resource exhaustion
        threads = []
        for i in range(3):
            thread = threading.Thread(target=rapid_request)
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        log.info("Resource exhaustion test completed")

    @task
    def fuzz_time_based_race_conditions(self):
        """Test time-based race conditions"""
        headers = {"Authorization": f"Bearer {self.token}"}

        # Test creating and immediately trying to use a credential
        credential_name = f"time_race_{uuid.uuid4()}"

        def create_and_use():
            # Create credential
            credential_data = {
                "name": credential_name,
                "username": "timeuser",
                "password": "timepass",
                "type": "OS"
            }

            create_response = self.client.post("/api/v3/raw-credentials",
                                               headers=headers,
                                               json=credential_data,
                                               verify=False,
                                               catch_response=True)

            if create_response.status_code == 200:
                try:
                    cred_id = create_response.json().get("id")
                    if cred_id:
                        # Immediately try to use the credential (GET)
                        get_response = self.client.get(f"/api/v3/raw-credentials/{cred_id}",
                                                       headers=headers,
                                                       verify=False,
                                                       catch_response=True)
                        return get_response.status_code
                except:
                    pass
            return create_response.status_code

        # Test multiple simultaneous create-and-use operations
        threads = []
        results = []

        for i in range(3):
            thread = threading.Thread(target=lambda: results.append(create_and_use()))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        success_count = sum(1 for status in results if status == 200)
        log.info(f"Time-based race condition test: {success_count} successful operations")

class RaceConditionUser(HttpUser):
    wait_time = constant(0.5)  # Shorter wait time for race conditions
    tasks = [RaceConditionFuzz]
    host = "https://localhost:8443"
