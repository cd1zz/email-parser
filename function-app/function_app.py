import azure.functions as func
import json
import logging
import base64
import os
import time
import uuid
import sys
import warnings
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

# Import the email parser components
from email_parser import create_email_parser
from shared.response_builder import ResponseBuilder
from shared.input_validator import InputValidator
from shared.error_handler import ErrorHandler

# Configure logging for Azure Functions
logging.basicConfig(level=logging.INFO)

app = func.FunctionApp()

# Configuration from environment variables with defaults
DEFAULT_CONFIG = {
    "log_level": os.getenv("LOG_LEVEL", "INFO"),
    "enable_url_analysis": os.getenv("DEFAULT_ENABLE_URL_ANALYSIS", "true").lower() == "true",
    "enable_url_expansion": os.getenv("DEFAULT_ENABLE_URL_EXPANSION", "false").lower() == "true",
    "expansion_timeout": int(os.getenv("DEFAULT_EXPANSION_TIMEOUT", "5")),
    "enable_document_processing": os.getenv("DEFAULT_ENABLE_DOCUMENT_PROCESSING", "true").lower() == "true",
    "document_text_limit": int(os.getenv("DEFAULT_DOCUMENT_TEXT_LIMIT", "10000")),
    "show_document_text": os.getenv("DEFAULT_SHOW_DOCUMENT_TEXT", "false").lower() == "true",
    "verbose": os.getenv("DEFAULT_VERBOSE", "false").lower() == "true",
    "max_file_size_mb": int(os.getenv("MAX_FILE_SIZE_MB", "50")),
    "function_timeout_seconds": int(os.getenv("FUNCTION_TIMEOUT_SECONDS", "300"))
}

# Global parser instance (for potential reuse to reduce cold starts)
_parser_cache = {}

# Environment validation results (cached)
_environment_validated = False
_environment_issues = []

def validate_environment():
    """
    Validate the Python environment and libraries for optimal compatibility.
    This helps users understand potential issues and provides guidance.
    """
    global _environment_validated, _environment_issues
    
    if _environment_validated:
        return _environment_issues
    
    issues = []
    
    # Check Python version
    python_version = sys.version_info
    if python_version.major != 3 or python_version.minor != 10:
        issues.append({
            "severity": "warning" if python_version.minor in [8, 9, 11, 12] else "error",
            "component": "python_version",
            "message": f"Python {python_version.major}.{python_version.minor} detected. "
                      f"This function is optimized for Python 3.10. "
                      f"Consider using Python 3.10 for best compatibility.",
            "recommendation": "Install Python 3.10 and recreate your virtual environment"
        })
    
    # Test critical library imports
    library_tests = [
        ("pdfminer.six", "from pdfminer.high_level import extract_text", "PDF text extraction"),
        ("pandas", "import pandas", "Excel document processing"),
        ("numpy", "import numpy", "Data processing (required by pandas)"),
        ("extract_msg", "import extract_msg", "Outlook .msg file parsing"),
        ("html2text", "import html2text", "HTML to text conversion"),
        ("azure_functions", "import azure.functions", "Azure Functions runtime")
    ]
    
    for lib_name, import_statement, purpose in library_tests:
        try:
            exec(import_statement)
        except ImportError as e:
            severity = "error" if lib_name in ["azure_functions"] else "warning"
            issues.append({
                "severity": severity,
                "component": lib_name,
                "message": f"Failed to import {lib_name} ({purpose}): {str(e)}",
                "recommendation": f"Install {lib_name} with: pip install {lib_name}"
            })
        except Exception as e:
            # Special handling for known issues
            if "DLL load failed" in str(e) and "pdfminer" in str(e):
                issues.append({
                    "severity": "error",
                    "component": "pdfminer.six",
                    "message": f"pdfminer has DLL/Rust compatibility issues: {str(e)}",
                    "recommendation": "Downgrade to pdfminer.six==20211012 (no Rust dependencies)"
                })
            elif "numpy" in str(e) and "source directory" in str(e):
                issues.append({
                    "severity": "error", 
                    "component": "numpy",
                    "message": f"numpy environment issue: {str(e)}",
                    "recommendation": "Reinstall numpy with: pip install --force-reinstall numpy==1.24.4"
                })
            else:
                issues.append({
                    "severity": "warning",
                    "component": lib_name,
                    "message": f"Unexpected error importing {lib_name}: {str(e)}",
                    "recommendation": f"Check {lib_name} installation and Python environment"
                })
    
    # Check for version conflicts
    try:
        import pdfminer
        if hasattr(pdfminer, '__version__'):
            version = pdfminer.__version__
            if version and int(version.split('.')[0]) >= 2025:
                issues.append({
                    "severity": "warning",
                    "component": "pdfminer.six",
                    "message": f"pdfminer.six version {version} may have Rust dependencies. "
                              "If you encounter DLL errors, consider downgrading.",
                    "recommendation": "Use: pip install pdfminer.six==20211012 for maximum compatibility"
                })
    except:
        pass
    
    _environment_validated = True
    _environment_issues = issues
    
    # Log environment status
    if not issues:
        logging.info("✅ Environment validation passed - all libraries compatible")
    else:
        error_count = sum(1 for issue in issues if issue["severity"] == "error")
        warning_count = sum(1 for issue in issues if issue["severity"] == "warning")
        
        if error_count > 0:
            logging.error(f"❌ Environment validation found {error_count} errors, {warning_count} warnings")
            for issue in issues:
                if issue["severity"] == "error":
                    logging.error(f"  ERROR - {issue['component']}: {issue['message']}")
        else:
            logging.warning(f"⚠️ Environment validation found {warning_count} warnings")
            
        for issue in issues:
            if issue["severity"] == "warning":
                logging.warning(f"  WARNING - {issue['component']}: {issue['message']}")
    
    return issues

def get_parser(config: Dict[str, Any]) -> Any:
    """Get or create an email parser with the given configuration."""
    # Validate environment on first parser creation
    env_issues = validate_environment()
    
    # Check for critical errors that would prevent parser creation
    critical_errors = [issue for issue in env_issues if issue["severity"] == "error"]
    if critical_errors:
        error_details = "; ".join([f"{issue['component']}: {issue['message']}" for issue in critical_errors])
        raise RuntimeError(f"Cannot create parser due to environment issues: {error_details}")
    
    # Create a cache key based on configuration
    cache_key = f"{config['enable_url_analysis']}_{config['enable_url_expansion']}_{config['enable_document_processing']}"
    
    if cache_key not in _parser_cache:
        logging.info(f"Creating new parser instance with config: {cache_key}")
        
        # Map log level string to logging constant
        log_level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR
        }
        log_level = log_level_map.get(config["log_level"], logging.INFO)
        
        _parser_cache[cache_key] = create_email_parser(
            log_level=log_level,
            enable_url_analysis=config["enable_url_analysis"],
            enable_url_expansion=config["enable_url_expansion"],
            expansion_timeout=config["expansion_timeout"],
            enable_document_processing=config["enable_document_processing"]
        )
    
    return _parser_cache[cache_key]

def extract_email_data_and_config(req: func.HttpRequest) -> Tuple[bytes, Optional[str], Dict[str, Any]]:
    """Extract email data and configuration from the HTTP request."""
    content_type = req.headers.get('content-type', '').lower()
    
    # Start with default configuration
    config = DEFAULT_CONFIG.copy()
    filename = None
    
    if content_type.startswith('application/json'):
        # JSON payload with base64 encoded email data
        try:
            json_data = req.get_json()
            if not json_data or 'email_data' not in json_data:
                raise ValueError("JSON payload must contain 'email_data' field")
            
            email_data = base64.b64decode(json_data['email_data'])
            filename = json_data.get('filename')
            
            # Override configuration if provided
            if 'options' in json_data:
                options = json_data['options']
                for key, value in options.items():
                    if key in config:
                        config[key] = value
                        
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid JSON payload: {e}")
            
    elif content_type.startswith('multipart/form-data'):
        # Multipart form data
        files = req.files
        if 'email_file' not in files:
            raise ValueError("Multipart request must contain 'email_file' field")
        
        email_file = files['email_file']
        email_data = email_file.read()
        filename = email_file.filename
        
        # Check for options in form data
        options_str = req.form.get('options')
        if options_str:
            try:
                options = json.loads(options_str)
                for key, value in options.items():
                    if key in config:
                        config[key] = value
            except json.JSONDecodeError:
                logging.warning("Invalid JSON in options field, using defaults")
                
    elif content_type.startswith('text/plain'):
        # Raw email text
        email_data = req.get_body()
        
    elif content_type.startswith('application/octet-stream'):
        # Binary email data
        email_data = req.get_body()
        
    else:
        # Try to get body as bytes (fallback)
        email_data = req.get_body()
        if not email_data:
            raise ValueError(f"Unsupported content type: {content_type}")
    
    return email_data, filename, config

@app.route(route="email-parse", methods=["POST"])
def email_parse(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to parse email files and extract structure, URLs, and document content.
    
    Supported input formats:
    1. Raw email text (text/plain)
    2. Binary email data (application/octet-stream)  
    3. JSON with base64 encoded data (application/json)
    4. Multipart form data with file upload (multipart/form-data)
    
    Returns JSON response with parsed email structure or error details.
    """
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    logging.info(f"Email parsing request started - Request ID: {request_id}")
    
    try:
        # Validate and extract input
        email_data, filename, config = extract_email_data_and_config(req)
        
        # Validate input
        InputValidator.validate_request(email_data, config)
        
        logging.info(f"Processing email: size={len(email_data)} bytes, filename={filename}")
        
        # Get parser instance (this will validate environment)
        parser = get_parser(config)
        
        # Parse the email
        parse_start = time.time()
        result = parser.parse(email_data, filename, verbose=config["verbose"])
        parse_time = time.time() - parse_start
        
        logging.info(f"Email parsing completed in {parse_time:.2f}s - Status: {result['status']}")
        
        # Post-process result based on configuration
        if not config["show_document_text"]:
            result = _truncate_document_text(result, config["document_text_limit"])
        
        # Build success response
        execution_time_ms = int((time.time() - start_time) * 1000)
        
        response_data = ResponseBuilder.build_success_response(
            email_analysis=result,
            request_id=request_id,
            execution_time_ms=execution_time_ms,
            config=config
        )
        
        logging.info(f"Request {request_id} completed successfully in {execution_time_ms}ms")
        
        return func.HttpResponse(
            body=json.dumps(response_data, default=str, ensure_ascii=False),
            mimetype="application/json",
            status_code=200
        )
        
    except ValueError as e:
        # Input validation or parsing errors
        logging.warning(f"Request {request_id} validation error: {e}")
        error_response = ErrorHandler.handle_validation_error(str(e), request_id)
        return func.HttpResponse(
            body=json.dumps(error_response, default=str),
            mimetype="application/json",
            status_code=400
        )
        
    except RuntimeError as e:
        # Environment validation errors
        logging.error(f"Request {request_id} environment error: {e}")
        error_response = ErrorHandler.handle_dependency_error(str(e), request_id)
        return func.HttpResponse(
            body=json.dumps(error_response, default=str),
            mimetype="application/json",
            status_code=503
        )
        
    except TimeoutError as e:
        # Processing timeout
        logging.error(f"Request {request_id} timeout: {e}")
        error_response = ErrorHandler.handle_timeout_error(str(e), request_id)
        return func.HttpResponse(
            body=json.dumps(error_response, default=str),
            mimetype="application/json",
            status_code=408
        )
        
    except Exception as e:
        # Unexpected errors
        logging.error(f"Request {request_id} unexpected error: {e}", exc_info=True)
        error_response = ErrorHandler.handle_unexpected_error(str(e), request_id)
        return func.HttpResponse(
            body=json.dumps(error_response, default=str),
            mimetype="application/json",
            status_code=500
        )

def _truncate_document_text(result: dict, text_limit: int) -> dict:
    """Truncate document text in the result to specified limit."""
    def truncate_in_structure(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == 'document_extracts' and isinstance(value, list):
                    for extract in value:
                        if isinstance(extract, dict) and 'text' in extract:
                            text = extract['text']
                            if text and len(text) > text_limit:
                                extract['text'] = text[:text_limit] + f"... [TRUNCATED - {len(text)} total chars]"
                                extract['truncated'] = True
                
                elif key == 'document_text' and isinstance(value, str):
                    if len(value) > text_limit:
                        data[key] = value[:text_limit] + f"... [TRUNCATED - {len(value)} total chars]"
                
                elif isinstance(value, (dict, list)):
                    truncate_in_structure(value)
        
        elif isinstance(data, list):
            for item in data:
                truncate_in_structure(item)
    
    truncate_in_structure(result)
    return result

@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint for monitoring with environment validation."""
    try:
        # Validate environment
        env_issues = validate_environment()
        
        # Test parser creation
        test_config = DEFAULT_CONFIG.copy()
        test_config["enable_url_expansion"] = False  # Avoid external dependencies in health check
        
        parser_available = False
        parser_error = None
        
        try:
            parser = get_parser(test_config)
            parser_available = parser is not None
        except Exception as e:
            parser_error = str(e)
        
        # Check optional library availability
        libraries_status = _check_library_availability()
        
        # Determine overall health status
        critical_errors = [issue for issue in env_issues if issue["severity"] == "error"]
        health_status = "healthy" if not critical_errors and parser_available else "degraded"
        if critical_errors:
            health_status = "unhealthy"
        
        health_data = {
            "status": health_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "parser_available": parser_available,
            "parser_error": parser_error,
            "libraries": libraries_status,
            "environment_validation": {
                "total_issues": len(env_issues),
                "errors": [issue for issue in env_issues if issue["severity"] == "error"],
                "warnings": [issue for issue in env_issues if issue["severity"] == "warning"],
                "recommendations": [issue["recommendation"] for issue in env_issues]
            },
            "configuration": {
                "max_file_size_mb": DEFAULT_CONFIG["max_file_size_mb"],
                "function_timeout_seconds": DEFAULT_CONFIG["function_timeout_seconds"],
                "default_document_processing": DEFAULT_CONFIG["enable_document_processing"],
                "default_url_analysis": DEFAULT_CONFIG["enable_url_analysis"]
            }
        }
        
        status_code = 200 if health_status == "healthy" else 503
        
        return func.HttpResponse(
            body=json.dumps(health_data, default=str),
            mimetype="application/json",
            status_code=status_code
        )
        
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        error_data = {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e)
        }
        
        return func.HttpResponse(
            body=json.dumps(error_data, default=str),
            mimetype="application/json",
            status_code=503
        )

def _check_library_availability() -> Dict[str, bool]:
    """Check availability of optional libraries."""
    libraries = {}
    
    library_tests = [
        ("pandas", "import pandas"),
        ("pdfminer", "from pdfminer.high_level import extract_text"),
        ("python_docx", "from docx import Document"),
        ("extract_msg", "import extract_msg"),
        ("html2text", "import html2text"),
        ("openpyxl", "import openpyxl"),
        ("xlrd", "import xlrd"),
        ("requests", "import requests")
    ]
    
    for lib_name, import_statement in library_tests:
        try:
            exec(import_statement)
            libraries[lib_name] = True
        except ImportError:
            libraries[lib_name] = False
        except Exception:
            libraries[lib_name] = False
    
    return libraries

@app.route(route="config", methods=["GET"])
def get_configuration(req: func.HttpRequest) -> func.HttpResponse:
    """Get current default configuration with environment status."""
    
    # Include environment validation in config response
    env_issues = validate_environment()
    
    config_info = {
        "default_configuration": DEFAULT_CONFIG,
        "environment_status": {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "recommended_python_version": "3.10.x",
            "environment_issues": env_issues,
            "total_issues": len(env_issues),
            "has_critical_errors": any(issue["severity"] == "error" for issue in env_issues)
        },
        "environment_variables": {
            "LOG_LEVEL": os.getenv("LOG_LEVEL", "not_set"),
            "MAX_FILE_SIZE_MB": os.getenv("MAX_FILE_SIZE_MB", "not_set"),
            "FUNCTION_TIMEOUT_SECONDS": os.getenv("FUNCTION_TIMEOUT_SECONDS", "not_set")
        },
        "supported_content_types": [
            "text/plain",
            "application/octet-stream", 
            "application/json",
            "multipart/form-data"
        ],
        "supported_email_formats": [
            ".eml",
            ".msg", 
            ".mbox"
        ],
        "supported_document_types": [
            ".pdf",
            ".doc",
            ".docx", 
            ".xls",
            ".xlsx"
        ]
    }
    
    return func.HttpResponse(
        body=json.dumps(config_info, default=str, indent=2),
        mimetype="application/json",
        status_code=200
    )