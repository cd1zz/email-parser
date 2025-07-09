"""Input validation for Azure Function email parser."""

import os
from typing import Dict, Any


class InputValidator:
    """Validates input data and configuration for the email parser function."""
    
    @staticmethod
    def validate_request(email_data: bytes, config: Dict[str, Any]) -> None:
        """
        Validate the email data and configuration.
        
        Args:
            email_data: The email data as bytes
            config: Configuration dictionary
            
        Raises:
            ValueError: If validation fails
        """
        # Validate email data
        InputValidator._validate_email_data(email_data, config)
        
        # Validate configuration
        InputValidator._validate_configuration(config)
    
    @staticmethod
    def _validate_email_data(email_data: bytes, config: Dict[str, Any]) -> None:
        """Validate the email data."""
        if not email_data:
            raise ValueError("Email data is empty")
        
        # Check file size limit
        max_size_bytes = config.get("max_file_size_mb", 50) * 1024 * 1024
        if len(email_data) > max_size_bytes:
            raise ValueError(
                f"Email data size ({len(email_data)} bytes) exceeds maximum allowed "
                f"size ({max_size_bytes} bytes)"
            )
        
        # Basic content validation
        if len(email_data) < 10:
            raise ValueError("Email data is too small to be a valid email")
        
        # Check for potential binary corruption or invalid content
        # FIXED: Don't flag MSG files which naturally contain null bytes (OLE format)
        if b'\x00' * 100 in email_data:
            # Check if this might be a valid MSG file (OLE compound document)
            if not email_data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                raise ValueError("Email data contains excessive null bytes (potential corruption)")
    
    @staticmethod
    def _validate_configuration(config: Dict[str, Any]) -> None:
        """Validate the configuration parameters."""
        # Validate timeout values
        expansion_timeout = config.get("expansion_timeout", 5)
        if not isinstance(expansion_timeout, int) or expansion_timeout < 1 or expansion_timeout > 30:
            raise ValueError("expansion_timeout must be an integer between 1 and 30 seconds")
        
        # Validate document text limit
        doc_text_limit = config.get("document_text_limit", 10000)
        if not isinstance(doc_text_limit, int) or doc_text_limit < 100:
            raise ValueError("document_text_limit must be an integer >= 100")
        
        # Validate boolean configuration values
        bool_configs = [
            "enable_url_analysis",
            "enable_url_expansion", 
            "enable_document_processing",
            "show_document_text",
            "verbose"
        ]
        
        for bool_config in bool_configs:
            if bool_config in config and not isinstance(config[bool_config], bool):
                raise ValueError(f"{bool_config} must be a boolean value")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        log_level = config.get("log_level", "INFO")
        if log_level not in valid_log_levels:
            raise ValueError(f"log_level must be one of: {valid_log_levels}")
    
    @staticmethod
    def validate_content_type(content_type: str) -> None:
        """
        Validate that the content type is supported.
        
        Args:
            content_type: The HTTP content type header
            
        Raises:
            ValueError: If content type is not supported
        """
        supported_types = [
            "text/plain",
            "application/octet-stream",
            "application/json", 
            "multipart/form-data"
        ]
        
        if not any(content_type.startswith(supported) for supported in supported_types):
            raise ValueError(
                f"Unsupported content type: {content_type}. "
                f"Supported types: {supported_types}"
            )
    
    @staticmethod
    def validate_filename(filename: str) -> None:
        """
        Validate filename for security and format compliance.
        
        Args:
            filename: The filename to validate
            
        Raises:
            ValueError: If filename is invalid
        """
        if not filename:
            return  # Filename is optional
        
        # Security checks
        if ".." in filename or "/" in filename or "\\" in filename:
            raise ValueError("Filename contains invalid path characters")
        
        # Length check
        if len(filename) > 255:
            raise ValueError("Filename is too long (max 255 characters)")
        
        # Check for null bytes
        if "\x00" in filename:
            raise ValueError("Filename contains null bytes")
        
        # Warn about potentially problematic extensions
        dangerous_extensions = [".exe", ".bat", ".cmd", ".scr", ".pif"]
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            raise ValueError(f"Filename has potentially dangerous extension: {filename}")
    
    @staticmethod 
    def check_security_constraints() -> None:
        """
        Check various security constraints and environment settings.
        
        Raises:
            ValueError: If security constraints are violated
        """
        # Check if running in a secure environment
        # This could include checks for:
        # - Required environment variables
        # - Security configurations
        # - Resource limits
        
        # Example: Check for required environment variables
        required_env_vars = []  # Add any required env vars here
        
        for env_var in required_env_vars:
            if not os.getenv(env_var):
                raise ValueError(f"Required environment variable {env_var} is not set")