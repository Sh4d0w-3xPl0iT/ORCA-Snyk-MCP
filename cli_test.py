#!/usr/bin/env python3
import os
import subprocess
import json
from dotenv import load_dotenv

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Print environment variables (don't print sensitive tokens)
    print("Environment variables loaded:")
    print(f"API_KEY set: {'Yes' if os.getenv('API_KEY') else 'No'}")
    print(f"ORCA_API_KEY set: {'Yes' if os.getenv('ORCA_API_KEY') else 'No'}")
    print(f"ORCA_TENANT set: {'Yes' if os.getenv('ORCA_TENANT') else 'No'}")
    print(f"SNYK_API_TOKEN set: {'Yes' if os.getenv('SNYK_API_TOKEN') else 'No'}")
    print(f"SNYK_TENANT set: {'Yes' if os.getenv('SNYK_TENANT') else 'No'}")
    
    # Check if required CLIs are installed
    try:
        snyk_version = subprocess.run(["snyk", "--version"], capture_output=True, text=True)
        print(f"Snyk CLI installed: {'Yes - ' + snyk_version.stdout.strip() if snyk_version.returncode == 0 else 'No'}")
    except FileNotFoundError:
        print("Snyk CLI not found in PATH")
    
    try:
        orca_version = subprocess.run(["orca", "--version"], capture_output=True, text=True)
        print(f"Orca CLI installed: {'Yes - ' + orca_version.stdout.strip() if orca_version.returncode == 0 else 'No'}")
    except FileNotFoundError:
        print("Orca CLI not found in PATH")
    
    # Test Snyk orgs command if Snyk is installed
    if 'Snyk CLI installed: Yes' in locals().get('snyk_version', ''):
        print("\nTesting Snyk organization lookup...")
        try:
            snyk_orgs = subprocess.run(["snyk", "orgs", "--json"], capture_output=True, text=True)
            if snyk_orgs.returncode == 0:
                try:
                    orgs_data = json.loads(snyk_orgs.stdout)
                    print(f"Found {len(orgs_data.get('orgs', []))} Snyk organizations:")
                    for org in orgs_data.get('orgs', []):
                        print(f"  - {org.get('name', 'Unknown')} (ID: {org.get('id', 'Unknown')})")
                except json.JSONDecodeError:
                    print("Error parsing Snyk organizations JSON output")
            else:
                print(f"Error running 'snyk orgs': {snyk_orgs.stderr}")
        except Exception as e:
            print(f"Error running Snyk orgs command: {str(e)}")
    
    print("\nTesting complete. This script confirms:")
    print("1. Environment variables are loaded from .env")
    print("2. CLI tools are detected correctly")
    print("3. Snyk organization lookup works (if Snyk is installed)")

if __name__ == "__main__":
    main() 