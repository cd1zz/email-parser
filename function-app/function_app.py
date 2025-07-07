import azure.functions as func
import json
import logging
import base64
import os
import time
import uuid
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

def get_parser(config: Dict[str, Any]) -> Any:
    """Get or create an email parser with the given configuration."""
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
        
        # Get parser instance
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
    """Health check endpoint for monitoring."""
    try:
        # Test parser creation
        test_config = DEFAULT_CONFIG.copy()
        test_config["enable_url_expansion"] = False  # Avoid external dependencies in health check
        parser = get_parser(test_config)
        
        # Check optional library availability
        libraries_status = _check_library_availability()
        
        health_data = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "parser_available": parser is not None,
            "libraries": libraries_status,
            "configuration": {
                "max_file_size_mb": DEFAULT_CONFIG["max_file_size_mb"],
                "function_timeout_seconds": DEFAULT_CONFIG["function_timeout_seconds"],
                "default_document_processing": DEFAULT_CONFIG["enable_document_processing"],
                "default_url_analysis": DEFAULT_CONFIG["enable_url_analysis"]
            }
        }
        
        return func.HttpResponse(
            body=json.dumps(health_data, default=str),
            mimetype="application/json",
            status_code=200
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
    
    # Check pandas
    try:
        import pandas
        libraries["pandas"] = True
    except ImportError:
        libraries["pandas"] = False
    
    # Check pdfminer
    try:
        from pdfminer.high_level import extract_text
        libraries["pdfminer"] = True
    except ImportError:
        libraries["pdfminer"] = False
    
    # Check python-docx
    try:
        from docx import Document
        libraries["python_docx"] = True
    except ImportError:
        libraries["python_docx"] = False
    
    # Check extract-msg
    try:
        import extract_msg
        libraries["extract_msg"] = True
    except ImportError:
        libraries["extract_msg"] = False
    
    # Check html2text
    try:
        import html2text
        libraries["html2text"] = True
    except ImportError:
        libraries["html2text"] = False
    
    return libraries

@app.route(route="config", methods=["GET"])
def get_configuration(req: func.HttpRequest) -> func.HttpResponse:
    """Get current default configuration."""
    config_info = {
        "default_configuration": DEFAULT_CONFIG,
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