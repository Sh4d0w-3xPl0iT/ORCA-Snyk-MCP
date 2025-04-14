#!/usr/bin/env python3
import os
import requests
from dotenv import load_dotenv

def test_snyk_token():
    """Test if the Snyk API token is valid by calling the Snyk API."""
    # Load environment variables
    load_dotenv()
    
    snyk_token = os.getenv("SNYK_API_TOKEN")
    
    if not snyk_token:
        print("❌ Snyk API token not found in .env file")
        return False
    
    print(f"Snyk API Token (first 10 chars): {snyk_token[:10]}...")
    
    # Try different potential Snyk API base URLs
    api_urls = [
        "https://api.snyk.io/api/v1",
        "https://api.eu.snyk.io/api/v1",  # EU instance
        "https://api.us.snyk.io/api/v1"   # US instance
    ]
    
    for base_url in api_urls:
        print(f"\nTrying Snyk API URL: {base_url}")
        
        # Headers with authentication
        headers = {
            "Authorization": f"token {snyk_token}",
            "Content-Type": "application/json"
        }
        
        # Try to get user organizations (a simple endpoint that requires authentication)
        try:
            url = f"{base_url}/orgs"
            print(f"Testing endpoint: {url}")
            
            response = requests.get(url, headers=headers, timeout=10)
            print(f"Status code: {response.status_code}")
            
            if response.status_code == 200:
                orgs = response.json().get("orgs", [])
                org_count = len(orgs)
                print(f"✅ Snyk API token is valid on {base_url}. Found {org_count} organizations.")
                
                if org_count > 0:
                    print("\nAvailable Snyk Organizations:")
                    for org in orgs:
                        print(f"  - {org.get('name')} (ID: {org.get('id')})")
                
                return True
            elif response.status_code == 401 or response.status_code == 403:
                print(f"Authentication failed on this URL")
                if response.text:
                    print(f"Response: {response.text[:200]}...")
            else:
                print(f"Got status code {response.status_code}")
                if response.text:
                    print(f"Response: {response.text[:200]}...")
        except Exception as e:
            print(f"Error with this URL: {str(e)}")
    
    print("\n❌ Could not authenticate with Snyk API using any of the tried servers")
    print("Please check your API token")
    return False

def test_orca_token():
    """Test if the Orca API key is valid by calling the Orca API."""
    # Load environment variables
    load_dotenv()
    
    orca_api_key = os.getenv("ORCA_API_KEY")
    orca_tenant = os.getenv("ORCA_TENANT")
    
    if not orca_api_key:
        print("❌ Orca API key not found in .env file")
        return False
    
    if not orca_tenant:
        print("❌ Orca tenant not found in .env file")
        return False
    
    print(f"Orca API Key (first 10 chars): {orca_api_key[:10]}...")
    print(f"Orca Tenant: {orca_tenant}")
    
    # Parse tenant to get actual domain
    tenant_domain = orca_tenant
    if not tenant_domain.startswith("http"):
        tenant_domain = f"https://{tenant_domain}"
    
    # Base URL for Orca API
    base_url = f"{tenant_domain}/api"
    print(f"Using base URL: {base_url}")
    
    # Headers with authentication
    # Try different auth formats as the correct one depends on Orca's API
    auth_formats = [
        {"Authorization": f"Bearer {orca_api_key}"},
        {"Authorization": f"Token {orca_api_key}"},
        {"x-api-key": orca_api_key},
        {"api-key": orca_api_key}
    ]
    
    for i, auth in enumerate(auth_formats):
        headers = {
            **auth,
            "Content-Type": "application/json"
        }
        
        print(f"\nTrying authentication format {i+1}: {list(auth.keys())[0]}")
        try:
            # Try a few common API endpoints that might work
            endpoints = ["/auth/me", "/user", "/users/me", "/orgs", "/projects"]
            
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                print(f"Testing endpoint: {url}")
                
                response = requests.get(url, headers=headers, timeout=10)
                print(f"Status code: {response.status_code}")
                
                if response.status_code == 200:
                    print("✅ Orca API key is valid with this endpoint!")
                    try:
                        print(f"Response: {response.json()}")
                    except:
                        print(f"Response (text): {response.text[:200]}...")
                    return True
                elif response.status_code == 401 or response.status_code == 403:
                    print(f"Authentication failed with this endpoint")
                    if response.text:
                        print(f"Response: {response.text[:200]}...")
                else:
                    print(f"Got status code {response.status_code}")
                    if response.text:
                        print(f"Response: {response.text[:200]}...")
                
        except Exception as e:
            print(f"Error with this authentication format: {str(e)}")
    
    print("\n❌ Could not authenticate with Orca API using any of the tried methods")
    print("Please check your API key and tenant information")
    return False

if __name__ == "__main__":
    print("Testing API tokens...")
    print("\n=== Snyk API Token Test ===")
    snyk_success = test_snyk_token()
    
    print("\n=== Orca API Key Test ===")
    orca_success = test_orca_token()
    
    print("\n=== Summary ===")
    print(f"Snyk API Token: {'✅ Valid' if snyk_success else '❌ Invalid'}")
    print(f"Orca API Key: {'✅ Valid' if orca_success else '❌ Invalid'}") 