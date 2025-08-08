import os
import json
import uuid
import requests
import time
from datetime import datetime
from dotenv import load_dotenv
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

class APIFuzzGenerator:
    def __init__(self):
        self.ai_endpoint = "https://ask.dell.com/api/v1/chat/completions"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('ASKDELL_API_KEY')}",
        }
        self.scenarios_dir = "scenarios"
        self.ensure_scenarios_dir()

    def ensure_scenarios_dir(self):
        """Create scenarios directory if it doesn't exist"""
        if not os.path.exists(self.scenarios_dir):
            os.makedirs(self.scenarios_dir)

    def generate_ids(self):
        """Generate required IDs for the API request"""
        session_id = ''.join([uuid.uuid4().hex[:10], uuid.uuid4().hex[:10]])
        chat_id = str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        return session_id, chat_id, request_id

    def create_fuzz_prompt(self, endpoint_info):
        """Create a prompt for generating fuzz test scenarios"""
        prompt = f"""
You are a security testing expert specializing in API fuzzing and penetration testing.
Generate comprehensive fuzz testing scenarios for the following API endpoint:

**API Endpoint Information:**
{endpoint_info}

**Requirements:**
1. Generate 20-30 different fuzz test scenarios
2. Include various attack vectors: SQL injection, XSS, command injection, buffer overflow, authentication bypass, authorization bypass, parameter pollution, etc.
3. For each scenario, provide:
   - Test case name
   - Description
   - HTTP method
   - Endpoint URL
   - Headers (if needed)
   - Request payload/body
   - Expected behavior
   - Risk level (Low/Medium/High/Critical)

**Focus Areas:**
- Input validation bypasses
- Authentication/Authorization flaws
- Injection attacks (SQL, NoSQL, LDAP, etc.)
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- File upload vulnerabilities
- Buffer overflow attempts
- Business logic flaws
- Rate limiting bypasses

**Output Format:**
Provide the response in JSON format with the following structure:
{{
  "endpoint": "endpoint_url",
  "generated_at": "timestamp",
  "scenarios": [
    {{
      "id": "scenario_id",
      "name": "Test Case Name",
      "description": "Detailed description",
      "risk_level": "High/Medium/Low/Critical",
      "method": "POST/GET/PUT/DELETE",
      "url": "full_endpoint_url",
      "headers": {{}},
      "payload": {{}},
      "expected_behavior": "What should happen",
      "attack_vector": "Type of attack"
    }}
  ]
}}

Generate realistic and comprehensive scenarios that would be used in professional security testing.
"""
        return prompt

    def send_request_to_ai(self, prompt):
        """Send request to AI endpoint and get response"""
        session_id, chat_id, request_id = self.generate_ids()

        payload = {
            "stream": False,  # Set to False to get complete response
            "model": "llama-3-1-8b-instruct",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "session_id": session_id,
            "chat_id": chat_id,
            "id": request_id,
            "currentOrganizationContext": "AskDell"
        }

        try:
            print(f"Sending request to AI endpoint...")
            response = requests.post(
                self.ai_endpoint,
                headers=self.headers,
                json=payload,
                verify=False,
                timeout=60
            )

            if response.status_code == 200:
                # Handle streaming response if needed
                if payload.get("stream", False):
                    return self.parse_streaming_response(response)
                else:
                    result = response.json()
                    if 'choices' in result and result['choices']:
                        return result['choices'][0]['message']['content']
                    else:
                        print("Unexpected response format")
                        return None
            else:
                print(f"AI API request failed: {response.status_code}")
                print(f"Response: {response.text}")
                return None

        except Exception as e:
            print(f"Error sending request to AI: {str(e)}")
            return None

    def parse_streaming_response(self, response):
        """Parse streaming response from AI endpoint"""
        full_response = ""
        try:
            for line in response.iter_lines():
                if line:
                    if line.startswith(b'data: '):
                        line = line[len(b'data: '):]
                    if line == b"[DONE]":
                        break
                    try:
                        json_line = json.loads(line.decode('utf-8'))
                        if 'choices' in json_line and json_line['choices']:
                            choice = json_line['choices'][0]
                            if 'delta' in choice and 'content' in choice['delta']:
                                content = choice['delta']['content']
                                full_response += content
                    except json.JSONDecodeError:
                        continue
            return full_response
        except Exception as e:
            print(f"Error parsing streaming response: {str(e)}")
            return None

    def save_scenarios(self, scenarios_data, endpoint_name):
        """Save generated scenarios to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fuzz_scenarios_{endpoint_name}_{timestamp}.json"
        filepath = os.path.join(self.scenarios_dir, filename)

        try:
            # Try to parse as JSON first
            if isinstance(scenarios_data, str):
                # Extract JSON from the response if it's wrapped in text
                start_idx = scenarios_data.find('{')
                end_idx = scenarios_data.rfind('}') + 1
                if start_idx != -1 and end_idx != 0:
                    json_str = scenarios_data[start_idx:end_idx]
                    parsed_data = json.loads(json_str)
                else:
                    # If no JSON found, create a wrapper
                    parsed_data = {
                        "endpoint": endpoint_name,
                        "generated_at": timestamp,
                        "raw_response": scenarios_data
                    }
            else:
                parsed_data = scenarios_data

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(parsed_data, f, indent=2, ensure_ascii=False)

            print(f"Scenarios saved to: {filepath}")
            return filepath

        except Exception as e:
            print(f"Error saving scenarios: {str(e)}")
            # Save as text file if JSON parsing fails
            txt_filename = f"fuzz_scenarios_{endpoint_name}_{timestamp}.txt"
            txt_filepath = os.path.join(self.scenarios_dir, txt_filename)
            with open(txt_filepath, 'w', encoding='utf-8') as f:
                f.write(str(scenarios_data))
            print(f"Saved as text file: {txt_filepath}")
            return txt_filepath

    def generate_fuzz_scenarios(self, endpoint_info, endpoint_name=None):
        """Main method to generate fuzz scenarios"""
        if not endpoint_name:
            endpoint_name = "api_endpoint"

        print(f"Generating fuzz scenarios for: {endpoint_name}")
        print(f"Endpoint info: {endpoint_info}")

        # Create prompt
        prompt = self.create_fuzz_prompt(endpoint_info)

        # Send to AI
        ai_response = self.send_request_to_ai(prompt)

        if ai_response:
            print("AI response received successfully")
            # Save scenarios
            filepath = self.save_scenarios(ai_response, endpoint_name)
            print(f"Fuzz scenarios generated and saved!")
            return filepath
        else:
            print("Failed to get response from AI")
            return None

def main():
    """Main function with example usage"""
    generator = APIFuzzGenerator()

    # Example endpoint information
    endpoint_info = """
    Endpoint: https://api.example.com/v1/users
    Method: POST
    Description: Create a new user account
    Parameters:
    - username (string, required): User's username
    - email (string, required): User's email address
    - password (string, required): User's password
    - role (string, optional): User role (admin, user, guest)
    - profile_data (object, optional): Additional profile information

    Authentication: Bearer token required
    Content-Type: application/json
    """

    # You can also accept input from user
    print("API Fuzz Scenario Generator")
    print("=" * 50)

    choice = input("Use example endpoint? (y/n): ").lower()

    if choice != 'y':
        print("\nEnter endpoint information:")
        endpoint_url = input("Endpoint URL: ")
        method = input("HTTP Method: ")
        description = input("Description: ")
        auth_required = input("Authentication required? (y/n): ")

        endpoint_info = f"""
        Endpoint: {endpoint_url}
        Method: {method}
        Description: {description}
        Authentication: {'Required' if auth_required.lower() == 'y' else 'Not required'}
        """

        # Extract endpoint name from URL for filename
        endpoint_name = endpoint_url.split('/')[-1] or "api_endpoint"
    else:
        endpoint_name = "users_api"

    # Generate scenarios
    result = generator.generate_fuzz_scenarios(endpoint_info, endpoint_name)

    if result:
        print(f"\n✅ Success! Scenarios saved to: {result}")
    else:
        print("\n❌ Failed to generate scenarios")

if __name__ == "__main__":
    main()
