from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import Optional, Dict, Any, List, Tuple
import os
import secrets
from dotenv import load_dotenv
import asyncio
import json
from pathlib import Path
import logging
import shutil

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
logger.info("Loading environment variables...")
load_dotenv()

# Define environment variables using simple os.getenv
API_KEY = os.getenv('API_KEY', '')
ORCA_API_KEY = os.getenv('ORCA_API_KEY', '')
ORCA_TENANT = os.getenv('ORCA_TENANT', '')
SNYK_API_TOKEN = os.getenv('SNYK_API_TOKEN', '')
SNYK_TENANT = os.getenv('SNYK_TENANT', '')

# Set Snyk region to EU based on test results
SNYK_REGION = os.getenv('SNYK_REGION', "eu")

logger.info(f"API_KEY: {'set' if API_KEY else 'not set'}")
logger.info(f"ORCA_API_KEY: {'set' if ORCA_API_KEY else 'not set'}")
logger.info(f"ORCA_TENANT: {'set' if ORCA_TENANT else 'not set'}")
logger.info(f"SNYK_API_TOKEN: {'set' if SNYK_API_TOKEN else 'not set'}")
logger.info(f"SNYK_TENANT: {'set' if SNYK_TENANT else 'not set'}")
logger.info(f"SNYK_REGION: {SNYK_REGION}")

# Validate environment variables
required_env_vars = ["API_KEY", "ORCA_API_KEY", "ORCA_TENANT", "SNYK_API_TOKEN", "SNYK_TENANT"]
missing_vars = []
if not API_KEY:
    missing_vars.append("API_KEY")
if not ORCA_API_KEY:
    missing_vars.append("ORCA_API_KEY")
if not ORCA_TENANT:
    missing_vars.append("ORCA_TENANT")
if not SNYK_API_TOKEN:
    missing_vars.append("SNYK_API_TOKEN")
if not SNYK_TENANT:
    missing_vars.append("SNYK_TENANT")

if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    logger.error("Please check your .env file")

# Check if CLIs are installed
logger.info("Checking CLI installations...")
def check_cli_installed(cli_name):
    return shutil.which(cli_name) is not None

orca_installed = check_cli_installed("orca")
snyk_installed = check_cli_installed("snyk")

logger.info(f"Orca CLI installed: {orca_installed}")
logger.info(f"Snyk CLI installed: {snyk_installed}")

if not orca_installed:
    logger.warning("Orca CLI not found in PATH. Orca scanning will not work.")
if not snyk_installed:
    logger.warning("Snyk CLI not found in PATH. Snyk scanning will not work.")

app = FastAPI(title="Secure MCP Server")

# Security - API key handling
API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

class ScanRequest(BaseModel):
    project_path: str
    scan_type: Optional[str] = "full"
    organization_id: Optional[str] = None

class ScanResponse(BaseModel):
    status: str
    results: Dict[str, Any]
    message: str

# --- Models for Snyk Orgs Endpoint ---
class SnykOrganization(BaseModel):
    name: str
    id: str

class SnykOrgsResponse(BaseModel):
    orgs: List[SnykOrganization]

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)):
    logger.info("Verifying API key...")
    if not secrets.compare_digest(api_key, API_KEY):
        logger.warning("Invalid API key provided.")
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    logger.info("API key verified successfully.")
    return api_key

@app.get("/health")
async def health_check(api_key: str = Depends(verify_api_key)):
    logger.info("Performing health check...")
    return {
        "status": "healthy", 
        "services": {
            "orca": orca_installed,
            "snyk": snyk_installed
        },
        "environment_loaded": True,
        "region_settings": {
            "snyk": SNYK_REGION
        }
    }

# --- Helper Functions ---

def _validate_project_path(project_path_str: str) -> Path:
    logger.info(f"Validating project path: {project_path_str}")
    """Validates the project path exists and is within the allowed directory.
    
    Performs checks to prevent path traversal vulnerabilities.
    """
    project_path = Path(project_path_str)
    if not project_path.exists():
        logger.error(f"Validation failed: Project path does not exist: {project_path}")
        raise HTTPException(status_code=400, detail=f"Project path does not exist: {project_path}")

    try:
        server_cwd = Path(os.getcwd()).resolve(strict=True)
        resolved_project_path = project_path.resolve(strict=True)
        
        # Check if the resolved path is relative to the server CWD to prevent path traversal
        resolved_project_path.relative_to(server_cwd)
        
    except FileNotFoundError:
        logger.error(f"Validation failed: Project path resolution failed for: {project_path}")
        raise HTTPException(status_code=400, detail=f"Invalid project path: {project_path}")
    except ValueError:
        logger.error(f"Validation failed: Project path is outside the allowed directory: {resolved_project_path}")
        raise HTTPException(status_code=400, detail=f"Project path is outside the allowed directory: {resolved_project_path}")
    except Exception as e:
        logger.error(f"Validation failed: Unexpected error validating path {project_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Error validating project path: {project_path}")
        
    logger.info(f"Project path validated successfully: {resolved_project_path}")
    return resolved_project_path

async def _run_cli_command(cmd: List[str]) -> Tuple[int, str, str]:
    logger.info(f"Executing CLI command: {' '.join(cmd)}")
    """Runs a CLI command asynchronously and returns status code, stdout, stderr."""
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await process.communicate()
    returncode = process.returncode
    stdout_str = stdout.decode().strip()
    stderr_str = stderr.decode().strip()
    logger.info(f"Command completed. Return code: {returncode}, Stdout length: {len(stdout_str)}, Stderr length: {len(stderr_str)}")
    return returncode, stdout_str, stderr_str

# --- New Endpoint for Snyk Orgs ---
@app.get("/snyk/organizations", response_model=SnykOrgsResponse)
async def get_snyk_organizations(api_key: str = Depends(verify_api_key)):
    logger.info("Fetching Snyk organizations...")
    """Retrieves the list of Snyk organizations accessible by the configured API token."""
    if not snyk_installed:
        raise HTTPException(
            status_code=503,
            detail="Snyk CLI not installed or not found in PATH"
        )

    try:
        # Run snyk orgs command
        snyk_cmd = ["snyk", "orgs", "--json"]
        
        # Add region flag for EU region
        if SNYK_REGION == "eu":
            snyk_cmd.insert(1, "--region=eu")
            
        returncode, stdout_str, stderr_str = await _run_cli_command(snyk_cmd)

        if returncode != 0:
            logger.error(f"Snyk orgs command failed (Code: {returncode}): {stderr_str}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to retrieve Snyk organizations: {stderr_str}"
            )

        # Try to parse the JSON output
        try:
            orgs_data = json.loads(stdout_str)
            if "orgs" not in orgs_data or not isinstance(orgs_data["orgs"], list):
                logger.error(f"Unexpected JSON structure from Snyk orgs: {stdout_str[:200]}...")
                raise HTTPException(
                   status_code=500, 
                   detail="Unexpected response format from Snyk CLI"
                )
            logger.info(f"Retrieved {len(orgs_data['orgs'])} organizations from Snyk.")
            return SnykOrgsResponse(orgs=orgs_data["orgs"])
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON from Snyk orgs: {stdout_str[:200]}...")
            raise HTTPException(
                status_code=500,
                detail="Failed to parse response from Snyk CLI"
            )

    except Exception as e:
        logger.exception("Error retrieving Snyk organizations")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred: {str(e)}"
        )

# --- API Endpoints ---
@app.post("/scan/orca", response_model=ScanResponse)
async def scan_orca(
    request: ScanRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Starting Orca scan for project: {request.project_path}, Scan type: {request.scan_type}")
    if not orca_installed:
        raise HTTPException(
            status_code=503,
            detail="Orca CLI not installed or not found in PATH"
        )
    
    try:
        # Validate project path using helper
        resolved_project_path = _validate_project_path(request.project_path)

        # Determine which tenant ID to use
        tenant_id = request.organization_id if request.organization_id else ORCA_TENANT
        logger.info(f"Using Orca tenant ID: {tenant_id}")

        # Run Orca CLI scan
        orca_cmd = [
            "orca",
            "scan",
            str(resolved_project_path),
            "--api-key", ORCA_API_KEY,
            "--tenant", tenant_id,
            "--format", "json"
        ]

        if request.scan_type == "quick":
            orca_cmd.append("--quick")

        # Run Orca scan using helper
        returncode, stdout_str, stderr_str = await _run_cli_command(orca_cmd)

        if returncode != 0:
            logger.error(f"Orca scan failed (Code: {returncode}): {stderr_str}")
            return ScanResponse(
                status="error",
                results={"error": stderr_str, "stdout": stdout_str},
                message=f"Orca scan failed with exit code {returncode}"
            )

        # Try to parse as JSON, fallback to text if not valid JSON
        try:
            results = json.loads(stdout_str)
        except json.JSONDecodeError:
            logger.warning(f"Orca output was not valid JSON: {stdout_str[:200]}...")
            results = {"raw_output": stdout_str}

        logger.info("Orca scan completed successfully.")
        return ScanResponse(
            status="success",
            results=results,
            message="Orca scan completed successfully"
        )

    except Exception as e:
        logger.exception("Error during Orca scan")
        raise HTTPException(
            status_code=500,
            detail=f"Error during Orca scan: {str(e)}"
        )

@app.post("/scan/snyk", response_model=ScanResponse)
async def scan_snyk(
    request: ScanRequest,
    api_key: str = Depends(verify_api_key)
):
    logger.info(f"Starting Snyk scan for project: {request.project_path}, Scan type: {request.scan_type}")
    if not snyk_installed:
        raise HTTPException(
            status_code=503,
            detail="Snyk CLI not installed or not found in PATH"
        )
        
    try:
        # Validate project path using helper
        resolved_project_path = _validate_project_path(request.project_path)

        # Determine which organization ID to use
        org_id = request.organization_id if request.organization_id else SNYK_TENANT
        logger.info(f"Using Snyk organization ID: {org_id}")

        # Run Snyk CLI scan
        snyk_cmd = [
            "snyk",
            "test",
            "--json",
            "--api-token", SNYK_API_TOKEN,
            "--org", org_id
        ]
        
        # Add region flag for EU region
        if SNYK_REGION == "eu":
            snyk_cmd.insert(1, "--region=eu")

        if request.scan_type == "quick":
            snyk_cmd.append("--severity-threshold=high")

        snyk_cmd.append(str(resolved_project_path))

        # Run Snyk scan using helper
        returncode, stdout_str, stderr_str = await _run_cli_command(snyk_cmd)

        if returncode not in [0, 1]:  # Snyk returns 1 when vulnerabilities are found
            logger.error(f"Snyk scan failed (Code: {returncode}): {stderr_str}")
            return ScanResponse(
                status="error",
                results={"error": stderr_str, "stdout": stdout_str},
                message=f"Snyk scan failed with exit code {returncode}"
            )

        # Try to parse as JSON, fallback to text if not valid JSON
        try:
            results = json.loads(stdout_str)
        except json.JSONDecodeError:
            logger.warning(f"Snyk output was not valid JSON: {stdout_str[:200]}...")
            results = {"raw_output": stdout_str}

        logger.info("Snyk scan completed successfully.")
        return ScanResponse(
            status="success",
            results=results,
            message="Snyk scan completed successfully"
        )

    except Exception as e:
        logger.exception("Error during Snyk scan")
        raise HTTPException(
            status_code=500,
            detail=f"Error during Snyk scan: {str(e)}"
        )

if __name__ == "__main__":
    logger.info("Initializing FastAPI server...")
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    logger.info(f"Starting server on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
