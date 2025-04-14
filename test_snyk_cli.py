#!/usr/bin/env python3
import os
import subprocess
import json
from dotenv import load_dotenv

def test_snyk_cli():
    """Test if the Snyk CLI works with the configured token."""
    # Load environment variables
    load_dotenv()
    
    snyk_token = os.getenv("SNYK_API_TOKEN")
    
    if not snyk_token:
        print("❌ Snyk API token not found in .env file")
        return False
    
    print(f"Snyk API Token (first 10 chars): {snyk_token[:10]}...")
    
    # Check if Snyk CLI is installed
    try:
        result = subprocess.run(["snyk", "--version"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Snyk CLI installed: {result.stdout.strip()}")
        else:
            print(f"❌ Snyk CLI check failed: {result.stderr}")
            return False
    except FileNotFoundError:
        print("❌ Snyk CLI not found in PATH")
        return False
    
    # Test Snyk orgs command with EU region
    try:
        # Set the environment variable temporarily for this test
        env = os.environ.copy()
        env["SNYK_API"] = snyk_token
        
        # Run command with EU region
        print("\nTesting 'snyk orgs' command with EU region...")
        result = subprocess.run(["snyk", "--region=eu", "orgs", "--json"], 
                              env=env, capture_output=True, text=True)
        
        if result.returncode == 0:
            try:
                orgs_data = json.loads(result.stdout)
                org_count = len(orgs_data.get("orgs", []))
                print(f"✅ Successfully retrieved {org_count} organizations")
                
                if org_count > 0:
                    print("\nAvailable Snyk Organizations:")
                    for org in orgs_data.get("orgs", []):
                        print(f"  - {org.get('name')} (ID: {org.get('id')})")
                return True
            except json.JSONDecodeError:
                print(f"❌ Failed to parse JSON response: {result.stdout[:200]}...")
                return False
        else:
            print(f"❌ Command failed (exit code {result.returncode}): {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing Snyk CLI: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing Snyk CLI configuration...")
    result = test_snyk_cli()
    print(f"\nOverall result: {'✅ Success' if result else '❌ Failed'}")
    
    if not result:
        print("\nTroubleshooting tips:")
        print("1. Ensure Snyk CLI is installed and in your PATH")
        print("2. Verify your API token is correct and not expired")
        print("3. Make sure .env file has the correct SNYK_API_TOKEN value")
        print("4. For EU region, ensure you're using the --region=eu flag") 