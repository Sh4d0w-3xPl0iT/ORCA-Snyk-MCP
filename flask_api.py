"""
Simplified Secure MCP Server using Flask instead of FastAPI
Compatible with Python 3.13
"""

from flask import Flask, request, jsonify
import os
import subprocess
import json
import secrets
from dotenv import load_dotenv
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Load API key and other settings from environment
API_KEY = os.getenv("API_KEY", "")
ORCA_API_KEY = os.getenv("ORCA_API_KEY", "")
ORCA_TENANT = os.getenv("ORCA_TENANT", "")
SNYK_API_TOKEN = os.getenv("SNYK_API_TOKEN", "")
SNYK_TENANT = os.getenv("SNYK_TENANT", "")

# Set the Snyk region to EU explicitly based on test results
SNYK_REGION = "eu"

# Check if required tools are installed
def check_cli_installed(cli_name):
    try:
        subprocess.run([cli_name, "--version"], capture_output=True)
        return True
    except FileNotFoundError:
        return False

orca_installed = check_cli_installed("orca")
snyk_installed = check_cli_installed("snyk")

if not orca_installed:
    logger.warning("Orca CLI not found in PATH. Orca scanning will not work.")
if not snyk_installed:
    logger.warning("Snyk CLI not found in PATH. Snyk scanning will not work.")

app = Flask(__name__)

# Helper function to verify API key
def verify_api_key(request):
    api_key = request.headers.get("X-API-Key", "")
    if not secrets.compare_digest(api_key, API_KEY):
        return False
    return True

# Helper function to validate project path
def validate_project_path(project_path_str):
    project_path = Path(project_path_str)
    if not project_path.exists():
        logger.error(f"Project path does not exist: {project_path}")
        return None, f"Project path does not exist: {project_path}"
    
    try:
        server_cwd = Path(os.getcwd()).resolve(strict=True)
        resolved_project_path = project_path.resolve(strict=True)
        resolved_project_path.relative_to(server_cwd)
        return resolved_project_path, None
    except Exception as e:
        logger.error(f"Error validating path: {str(e)}")
        return None, f"Invalid project path: {str(e)}"

# Helper function to run CLI commands
def run_cli_command(cmd):
    logger.info(f"Running command: {' '.join(cmd)}")
    process = subprocess.run(cmd, capture_output=True, text=True)
    return process.returncode, process.stdout, process.stderr

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    if not verify_api_key(request):
        return jsonify({"error": "Invalid API key"}), 403
    
    return jsonify({
        "status": "healthy",
        "services": {
            "orca": orca_installed,
            "snyk": snyk_installed
        },
        "environment_loaded": True,
        "region_settings": {
            "snyk": SNYK_REGION
        }
    })

# Snyk organizations endpoint
@app.route("/snyk/organizations", methods=["GET"])
def get_snyk_organizations():
    if not verify_api_key(request):
        return jsonify({"error": "Invalid API key"}), 403
    
    if not snyk_installed:
        return jsonify({"error": "Snyk CLI not installed"}), 503
    
    try:
        # Use region-specific flag for Snyk CLI
        snyk_cmd = ["snyk", "orgs", "--json"]
        
        # Add region flag for EU region
        if SNYK_REGION == "eu":
            snyk_cmd.insert(1, "--region=eu")
        
        returncode, stdout, stderr = run_cli_command(snyk_cmd)
        
        if returncode != 0:
            logger.error(f"Snyk orgs command failed: {stderr}")
            return jsonify({"error": f"Failed to retrieve organizations: {stderr}"}), 500
        
        try:
            orgs_data = json.loads(stdout)
            if "orgs" not in orgs_data or not isinstance(orgs_data["orgs"], list):
                return jsonify({"error": "Unexpected response format"}), 500
            
            return jsonify({"orgs": orgs_data["orgs"]})
        except json.JSONDecodeError:
            return jsonify({"error": "Failed to parse response"}), 500
    
    except Exception as e:
        logger.exception("Error retrieving organizations")
        return jsonify({"error": str(e)}), 500

# Orca scan endpoint
@app.route("/scan/orca", methods=["POST"])
def scan_orca():
    if not verify_api_key(request):
        return jsonify({"error": "Invalid API key"}), 403
    
    if not orca_installed:
        return jsonify({"error": "Orca CLI not installed"}), 503
    
    try:
        data = request.json
        if not data or not data.get("project_path"):
            return jsonify({"error": "Project path is required"}), 400
        
        project_path = data.get("project_path")
        scan_type = data.get("scan_type", "full")
        organization_id = data.get("organization_id")
        
        # Validate project path
        resolved_path, error = validate_project_path(project_path)
        if error:
            return jsonify({"error": error}), 400
        
        # Determine which tenant ID to use
        tenant_id = organization_id if organization_id else ORCA_TENANT
        logger.info(f"Using Orca tenant ID: {tenant_id}")
        
        # Run Orca scan
        orca_cmd = [
            "orca",
            "scan",
            str(resolved_path),
            "--api-key", ORCA_API_KEY,
            "--tenant", tenant_id,
            "--format", "json"
        ]
        
        if scan_type == "quick":
            orca_cmd.append("--quick")
        
        returncode, stdout, stderr = run_cli_command(orca_cmd)
        
        if returncode != 0:
            logger.error(f"Orca scan failed: {stderr}")
            return jsonify({
                "status": "error",
                "results": {"error": stderr, "stdout": stdout},
                "message": f"Orca scan failed with exit code {returncode}"
            })
        
        try:
            results = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning(f"Orca output was not valid JSON")
            results = {"raw_output": stdout}
        
        return jsonify({
            "status": "success",
            "results": results,
            "message": "Orca scan completed successfully"
        })
    
    except Exception as e:
        logger.exception("Error during Orca scan")
        return jsonify({"error": str(e)}), 500

# Snyk scan endpoint
@app.route("/scan/snyk", methods=["POST"])
def scan_snyk():
    if not verify_api_key(request):
        return jsonify({"error": "Invalid API key"}), 403
    
    if not snyk_installed:
        return jsonify({"error": "Snyk CLI not installed"}), 503
    
    try:
        data = request.json
        if not data or not data.get("project_path"):
            return jsonify({"error": "Project path is required"}), 400
        
        project_path = data.get("project_path")
        scan_type = data.get("scan_type", "full")
        organization_id = data.get("organization_id")
        
        # Validate project path
        resolved_path, error = validate_project_path(project_path)
        if error:
            return jsonify({"error": error}), 400
        
        # Determine which organization ID to use
        org_id = organization_id if organization_id else SNYK_TENANT
        logger.info(f"Using Snyk organization ID: {org_id}")
        
        # Run Snyk scan
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
        
        if scan_type == "quick":
            snyk_cmd.append("--severity-threshold=high")
        
        snyk_cmd.append(str(resolved_path))
        
        returncode, stdout, stderr = run_cli_command(snyk_cmd)
        
        # Snyk returns 1 when vulnerabilities are found (normal behavior)
        if returncode not in [0, 1]:
            logger.error(f"Snyk scan failed: {stderr}")
            return jsonify({
                "status": "error",
                "results": {"error": stderr, "stdout": stdout},
                "message": f"Snyk scan failed with exit code {returncode}"
            })
        
        try:
            results = json.loads(stdout)
        except json.JSONDecodeError:
            logger.warning(f"Snyk output was not valid JSON")
            results = {"raw_output": stdout}
        
        return jsonify({
            "status": "success",
            "results": results,
            "message": "Snyk scan completed successfully"
        })
    
    except Exception as e:
        logger.exception("Error during Snyk scan")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=True) 