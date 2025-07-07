"""Error handling for Azure Function email parser."""

import logging
from datetime import datetime, timezone
from typing import Dict, Any


class ErrorHandler:
    """Centralized error handling for the email parser function."""
    
    @staticmethod
    def handle_validation_error(error_message: str, request_id: str) -> Dict[str, Any]:
        """Handle input validation errors (400 Bad Request)."""
        return ErrorHandler._build_error_response(
            code="VALIDATION_ERROR",
            message="Request validation failed",
            details=error_message,
            request_id=request_id,
            log_level=logging.WARNING
        )
    
    @staticmethod
    def handle_parsing_error(error_message: str, request_id: str) -> Dict[str, Any]:
        """Handle email parsing errors (422 Unprocessable Entity)."""
        return ErrorHandler._build_error_response(
            code="PARSING_ERROR", 
            message="Failed to parse email content",
            details=error_message,
            request_id=request_id,
            log_level=logging.ERROR
        )
    
    @staticmethod
    def handle_timeout_error(error_message: str, request_id: str) -> Dict[str, Any]:
        """Handle processing timeout errors (408 Request Timeout)."""
        return ErrorHandler._build_error_response(
            code="TIMEOUT_ERROR",
            message="Email processing timed out",
            details=error_message,
            request_id=request_id,
            log_level=logging.ERROR
        )
    
    @staticmethod
    def handle_file_size_error(file_size: int, max_size: int, request_id: str) -> Dict[str, Any]:
        """Handle file size limit errors (413 Payload Too Large)."""
        return ErrorHandler._build_error_response(
            code="FILE_TOO_LARGE",
            message="Email file exceeds size limit",
            details=f"File size: {file_size} bytes, Maximum allowed: {max_size} bytes",
            request_id=request_id,
            log_level=logging.WARNING
        )
    
    @staticmethod
    def handle_unsupported_format_error(format_info: str, request_id: str) -> Dict[str, Any]:
        """Handle unsupported file format errors (415 Unsupported Media Type)."""
        return ErrorHandler._build_error_response(
            code="UNSUPPORTED_FORMAT",
            message="Email format is not supported",
            details=format_info,
            request_id=request_id,
            log_level=logging.WARNING
        )
    
    @staticmethod
    def handle_resource_limit_error(error_message: str, request_id: str) -> Dict[str, Any]:
        """Handle resource limit errors (507 Insufficient Storage)."""
        return ErrorHandler._build_error_response(
            code="RESOURCE_LIMIT_EXCEEDED",
            message="Processing resource limits exceeded",
            details=error_message,
            request_id=request_id,
            log_level=logging.ERROR
        )
    
    @staticmethod
    def handle_unexpected_error(error_message: str, request_id: str) -> Dict[str, Any]:
        """Handle unexpected internal errors (500 Internal Server Error)."""
        return ErrorHandler._build_error_response(
            code="INTERNAL_ERROR",
            message="An unexpected error occurred during processing",
            details=f"Internal error: {error_message}",
            request_id=request_id,
            log_level=logging.ERROR
        )
    
    @staticmethod
    def handle_dependency_error(missing_library: str, request_id: str) -> Dict[str, Any]:
        """Handle missing dependency errors (503 Service Unavailable)."""
        return ErrorHandler._build_error_response(
            code="DEPENDENCY_ERROR",
            message="Required processing library is not available",
            details=f"Missing library: {missing_library}",
            request_id=request_id,
            log_level=logging.ERROR
        )
    
    @staticmethod
    def _build_error_response(
        code: str,
        message: str, 
        details: str,
        request_id: str,
        log_level: int = logging.ERROR
    ) -> Dict[str, Any]:
        """
        Build a standardized error response.
        
        Args:
            code: Error code for categorization
            message: User-friendly error message
            details: Detailed error information
            request_id: Unique request identifier
            log_level: Logging level for this error
            
        Returns:
            Standardized error response dictionary
        """
        # Log the error
        log_message = f"Request {request_id} error [{code}]: {message} - {details}"
        
        if log_level == logging.WARNING:
            logging.warning(log_message)
        elif log_level == logging.ERROR:
            logging.error(log_message)
        else:
            logging.info(log_message)
        
        return {
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "error": {
                "code": code,
                "message": message,
                "details": details
            },
            "troubleshooting": ErrorHandler._get_troubleshooting_info(code)
        }
    
    @staticmethod
    def _get_troubleshooting_info(error_code: str) -> Dict[str, Any]:
        """Get troubleshooting information for specific error codes."""
        troubleshooting_guide = {
            "VALIDATION_ERROR": {
                "common_causes": [
                    "Empty or missing email data",
                    "Invalid configuration parameters",
                    "Unsupported content type"
                ],
                "solutions": [
                    "Ensure email data is provided in the request body",
                    "Check that all configuration values are valid",
                    "Use supported content types: text/plain, application/octet-stream, application/json, multipart/form-data"
                ]
            },
            "PARSING_ERROR": {
                "common_causes": [
                    "Corrupted email file",
                    "Unsupported email format",
                    "Invalid email structure"
                ],
                "solutions": [
                    "Verify the email file is not corrupted",
                    "Ensure the email is in a supported format (.eml, .msg, .mbox)",
                    "Try with a different email file to isolate the issue"
                ]
            },
            "TIMEOUT_ERROR": {
                "common_causes": [
                    "Large email with many attachments",
                    "Complex document processing",
                    "URL expansion taking too long"
                ],
                "solutions": [
                    "Disable document processing for faster parsing",
                    "Disable URL expansion to avoid network delays",
                    "Try processing smaller email files"
                ]
            },
            "FILE_TOO_LARGE": {
                "common_causes": [
                    "Email file exceeds size limit",
                    "Large attachments in email"
                ],
                "solutions": [
                    "Reduce email file size",
                    "Remove large attachments before processing",
                    "Use a different email processing service for large files"
                ]
            },
            "UNSUPPORTED_FORMAT": {
                "common_causes": [
                    "Email format not recognized",
                    "Incorrect file extension"
                ],
                "solutions": [
                    "Ensure email is in .eml, .msg, or .mbox format",
                    "Check file extension matches content",
                    "Convert email to a supported format"
                ]
            },
            "DEPENDENCY_ERROR": {
                "common_causes": [
                    "Optional processing library not installed",
                    "Library version incompatibility"
                ],
                "solutions": [
                    "Disable features requiring missing libraries",
                    "Contact administrator to install required libraries",
                    "Use basic parsing without advanced features"
                ]
            },
            "INTERNAL_ERROR": {
                "common_causes": [
                    "Unexpected system error",
                    "Memory or resource constraints",
                    "Code bug or edge case"
                ],
                "solutions": [
                    "Try the request again after a short delay",
                    "Use simpler configuration options",
                    "Contact support if the error persists"
                ]
            }
        }
        
        return troubleshooting_guide.get(error_code, {
            "common_causes": ["Unknown error"],
            "solutions": ["Contact support for assistance"]
        })