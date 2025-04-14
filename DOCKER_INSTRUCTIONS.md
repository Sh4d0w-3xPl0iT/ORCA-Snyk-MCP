# Testing with Docker

To run the application with Docker (recommended for resolving compatibility issues with Python 3.13):

1. Build the Docker image:
   ```
   docker build -t secure-mcp-server .
   ```

2. Run the Docker container:
   ```
   docker run -p 8000:8000 --env-file .env secure-mcp-server
   ```

3. The server will be available at http://localhost:8000

4. You can test the API endpoints:
   
   Health check:
   ```
   curl http://localhost:8000/health -H "X-API-Key: test_api_key_123"
   ```
   
   Snyk Organizations:
   ```
   curl http://localhost:8000/snyk/organizations -H "X-API-Key: test_api_key_123"
   ```
   
   Snyk Scan:
   ```
   curl -X POST http://localhost:8000/scan/snyk -H "X-API-Key: test_api_key_123" -H "Content-Type: application/json" -d "{\"project_path\": \".\", \"scan_type\": \"quick\"}"
   ```
   
   Snyk Scan with custom organization ID:
   ```
   curl -X POST http://localhost:8000/scan/snyk -H "X-API-Key: test_api_key_123" -H "Content-Type: application/json" -d "{\"project_path\": \".\", \"scan_type\": \"quick\", \"organization_id\": \"custom_org_id\"}"
   ```

Note: The container will need access to Snyk and Orca CLIs. For proper functionality, you might need to build a more complex Docker image that includes these CLI tools. 