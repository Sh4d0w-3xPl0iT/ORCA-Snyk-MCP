# Secure MCP Server for Orca and Snyk CLI Integration

This Model Context Protocol (MCP) server provides integration for Orca and Snyk CLI scanning capabilities within the IDE environment.

## Features

- Orca CLI scanning integration
- Snyk CLI scanning integration
- Secure API endpoints for IDE integration
- Environment-based configuration

## Prerequisites

- Python 3.8+
- Orca CLI installed and configured
- Snyk CLI installed and configured
- Access to EU tenant for both Orca and Snyk

## Setup

1. Clone this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Create a `.env` file with your configuration:
   ```
   ORCA_API_KEY=your_orca_api_key
   SNYK_API_TOKEN=your_snyk_api_token
   ORCA_TENANT=your_orca_tenant
   SNYK_TENANT=your_snyk_tenant
   ```

## Running the Server

```bash
uvicorn main:app --reload
```

The server will start on `http://localhost:8000`

## API Endpoints

- `POST /scan/orca`: Trigger Orca scan. 
  - **Request Body:** 
    - `project_path` (string, required): Path to the project.
    - `scan_type` (string, optional): "full" or "quick". Defaults to "full".
    - `organization_id` (string, optional): Orca tenant ID to use. Defaults to `ORCA_TENANT` from `.env`.
- `POST /scan/snyk`: Trigger Snyk scan.
  - **Request Body:**
    - `project_path` (string, required): Path to the project.
    - `scan_type` (string, optional): "full" or "quick". Defaults to "full".
    - `organization_id` (string, optional): Snyk organization ID to use. Defaults to `SNYK_TENANT` from `.env`.
- `GET /health`: Health check endpoint.
- `GET /snyk/organizations`: Retrieve the list of Snyk organizations accessible by the configured API token.
  - **Response Body:**
    - `orgs` (array): List of organization objects, each containing `name` (string) and `id` (string).

## EU Region Configuration

This implementation is specifically configured to use the EU region for Snyk API calls, based on test results.
The Snyk API token works correctly with the EU endpoint (api.eu.snyk.io).

All Snyk CLI commands will automatically include the `--region=eu` flag when executed.

## Security

- All API endpoints require authentication
- API keys and tokens are stored securely in environment variables
- EU tenant compliance maintained

## Alternative Flask Implementation

Due to compatibility issues between FastAPI and Python 3.13, an alternative Flask implementation is provided:

1. Install Flask dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the Flask server:
   ```bash
   python flask_api.py
   ```

The Flask implementation provides the same API endpoints with identical functionality:
- `GET /health` - Health check endpoint
- `GET /snyk/organizations` - Retrieve Snyk organizations 
- `POST /scan/orca` - Run Orca scans
- `POST /scan/snyk` - Run Snyk scans

All endpoints require the `X-API-Key` header and support the same request parameters, including the new `organization_id` parameter for the scan endpoints.

## Testing the Implementation

A simple test script is provided to verify environment variables and basic CLI functionality:

```bash
python cli_test.py
```

This will check that environment variables are loaded correctly and test basic CLI interactions.

## Development

This project uses FastAPI for the server implementation and follows RESTful API best practices. 