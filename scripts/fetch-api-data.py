import requests
import json
import sys
from datetime import datetime
import urllib3
from dotenv import load_dotenv
import os

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

class StoplightAPIFetcher:
    def __init__(self):
        self.base_url = "https://stoplight.dell.com/api/v1/projects/cHJqOjY0NDg/table-of-contents"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin"
        }
        self.session = requests.Session()

    def fetch_table_of_contents(self, branch="master", format_output=True):
        """
        Fetch the table of contents from Stoplight API

        Args:
            branch (str): Git branch to fetch from (default: master)
            format_output (bool): Whether to format and print the output

        Returns:
            dict: API response data
        """
        url = f"{self.base_url}?branch={branch}"

        try:
            print(f"Fetching API data from: {url}")
            print("=" * 60)

            response = self.session.get(
                url,
                headers=self.headers,
                verify=False,  # Disable SSL verification if needed
                timeout=30
            )

            print(f"Status Code: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print("=" * 60)

            if response.status_code == 200:
                try:
                    data = response.json()

                    if format_output:
                        self.print_formatted_data(data)

                    return data

                except json.JSONDecodeError as e:
                    print(f"❌ Failed to decode JSON response: {e}")
                    print(f"Raw response: {response.text[:500]}...")
                    return None

            else:
                print(f"❌ API request failed with status code: {response.status_code}")
                print(f"Response: {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            return None

    def print_formatted_data(self, data):
        """
        Print the API data in a formatted, readable way

        Args:
            data (dict): API response data
        """
        print("📋 STOPLIGHT API DATA")
        print("=" * 60)
        print(f"Fetched at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        if isinstance(data, dict):
            self.print_dict_data(data, level=0)
        elif isinstance(data, list):
            self.print_list_data(data, level=0)
        else:
            print(f"Data type: {type(data)}")
            print(f"Content: {data}")

    def print_dict_data(self, data, level=0):
        """Print dictionary data with proper indentation"""
        indent = "  " * level

        for key, value in data.items():
            if isinstance(value, dict):
                print(f"{indent}📁 {key}:")
                self.print_dict_data(value, level + 1)
            elif isinstance(value, list):
                print(f"{indent}📋 {key} ({len(value)} items):")
                self.print_list_data(value, level + 1)
            else:
                # Truncate long values for readability
                str_value = str(value)
                if len(str_value) > 100:
                    str_value = str_value[:100] + "..."
                print(f"{indent}📄 {key}: {str_value}")

    def print_list_data(self, data, level=0):
        """Print list data with proper formatting"""
        indent = "  " * level

        for i, item in enumerate(data):
            if isinstance(item, dict):
                print(f"{indent}[{i}] 📁 Dictionary:")
                self.print_dict_data(item, level + 1)
            elif isinstance(item, list):
                print(f"{indent}[{i}] 📋 List ({len(item)} items):")
                self.print_list_data(item, level + 1)
            else:
                str_item = str(item)
                if len(str_item) > 100:
                    str_item = str_item[:100] + "..."
                print(f"{indent}[{i}] 📄 {str_item}")

            if i < len(data) - 1:
                print()

    def save_to_file(self, data, filename=None):
        """
        Save the fetched data to a JSON file

        Args:
            data (dict): API response data
            filename (str): Custom filename (optional)

        Returns:
            str: Path to saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"stoplight_api_data_{timestamp}.json"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            print(f"💾 Data saved to: {filename}")
            return filename

        except Exception as e:
            print(f"❌ Failed to save data: {e}")
            return None

    def search_in_data(self, data, search_term, case_sensitive=False):
        """
        Search for specific terms in the API data

        Args:
            data: API response data
            search_term (str): Term to search for
            case_sensitive (bool): Whether search should be case sensitive

        Returns:
            list: Found matches with their paths
        """
        matches = []

        def search_recursive(obj, path="root"):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}"

                    # Search in key
                    key_str = str(key)
                    if not case_sensitive:
                        key_str = key_str.lower()
                        term = search_term.lower()
                    else:
                        term = search_term

                    if term in key_str:
                        matches.append({
                            "type": "key",
                            "path": new_path,
                            "value": key,
                            "content": value
                        })

                    # Search in value
                    if isinstance(value, str):
                        val_str = value if case_sensitive else value.lower()
                        if term in val_str:
                            matches.append({
                                "type": "value",
                                "path": new_path,
                                "value": value,
                                "content": value
                            })

                    search_recursive(value, new_path)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    search_recursive(item, f"{path}[{i}]")

            elif isinstance(obj, str):
                obj_str = obj if case_sensitive else obj.lower()
                term = search_term if case_sensitive else search_term.lower()
                if term in obj_str:
                    matches.append({
                        "type": "string",
                        "path": path,
                        "value": obj,
                        "content": obj
                    })

        search_recursive(data)
        return matches

    def analyze_api_structure(self, data):
        """
        Analyze and print the structure of the API data

        Args:
            data: API response data
        """
        print("🔍 API DATA ANALYSIS")
        print("=" * 60)

        def analyze_recursive(obj, path="root", level=0):
            indent = "  " * level

            if isinstance(obj, dict):
                print(f"{indent}📁 {path} (dict, {len(obj)} keys)")
                for key in obj.keys():
                    analyze_recursive(obj[key], key, level + 1)

            elif isinstance(obj, list):
                print(f"{indent}📋 {path} (list, {len(obj)} items)")
                if obj:  # If list is not empty, analyze first item
                    analyze_recursive(obj[0], f"{path}[0]", level + 1)

            else:
                data_type = type(obj).__name__
                value_preview = str(obj)[:50] + ("..." if len(str(obj)) > 50 else "")
                print(f"{indent}📄 {path} ({data_type}): {value_preview}")

        analyze_recursive(data)

def main():
    """Main function with interactive options"""
    fetcher = StoplightAPIFetcher()

    print("🚀 Stoplight Dell API Data Fetcher")
    print("=" * 50)

    # Get branch input
    branch = input("Enter branch name (default: master): ").strip()
    if not branch:
        branch = "master"

    # Fetch data
    data = fetcher.fetch_table_of_contents(branch=branch)

    if data:
        print("\n✅ Data fetched successfully!")

        # Interactive options
        while True:
            print("\n" + "=" * 50)
            print("Choose an option:")
            print("1. Print formatted data")
            print("2. Save to JSON file")
            print("3. Search in data")
            print("4. Analyze structure")
            print("5. Print raw JSON")
            print("6. Exit")

            choice = input("\nEnter your choice (1-6): ").strip()

            if choice == "1":
                print("\n" + "=" * 50)
                fetcher.print_formatted_data(data)

            elif choice == "2":
                filename = input("Enter filename (or press Enter for auto): ").strip()
                if not filename:
                    filename = None
                fetcher.save_to_file(data, filename)

            elif choice == "3":
                search_term = input("Enter search term: ").strip()
                if search_term:
                    case_sensitive = input("Case sensitive? (y/n): ").strip().lower() == 'y'
                    matches = fetcher.search_in_data(data, search_term, case_sensitive)

                    print(f"\n🔍 Found {len(matches)} matches for '{search_term}':")
                    for match in matches:
                        print(f"  {match['type']} at {match['path']}: {match['value']}")

            elif choice == "4":
                print()
                fetcher.analyze_api_structure(data)

            elif choice == "5":
                print("\n📄 RAW JSON DATA:")
                print("=" * 50)
                print(json.dumps(data, indent=2))

            elif choice == "6":
                print("👋 Goodbye!")
                break

            else:
                print("❌ Invalid choice. Please try again.")

    else:
        print("❌ Failed to fetch data. Please check the URL and try again.")

if __name__ == "__main__":
    main()
