# Email Parser Configuration Reference

## Overview

The Email Parser now uses a centralized configuration management system that consolidates all hardcoded values into a single, easily manageable location. This allows users to customize the parser's behavior without modifying source code.

## Configuration Files

### Primary Configuration
- **Location:** `shared/config.py`
- **Purpose:** Centralized configuration class with all configurable values
- **Environment Variables:** All settings can be overridden via environment variables

### Environment Variable Prefix
All environment variables use the prefix `EP_` (Email Parser) to avoid conflicts.

## Configuration Categories

### File Size and Processing Limits

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `MAX_FILE_SIZE_MB` | `EP_MAX_FILE_SIZE_MB` | 50 | Maximum email file size in MB |
| `MIN_EMAIL_SIZE_BYTES` | `EP_MIN_EMAIL_SIZE_BYTES` | 10 | Minimum email size in bytes |
| `MAX_NULL_BYTES` | `EP_MAX_NULL_BYTES` | 100 | Maximum consecutive null bytes before flagging corruption |
| `MAX_FILENAME_LENGTH` | `EP_MAX_FILENAME_LENGTH` | 255 | Maximum filename length |
| `DOCUMENT_TEXT_LIMIT` | `EP_DOCUMENT_TEXT_LIMIT` | 10000 | Maximum characters to extract from documents |
| `DOCUMENT_TEXT_LIMIT_MIN` | `EP_DOCUMENT_TEXT_LIMIT_MIN` | 100 | Minimum allowed document text limit |

### Timeout Configuration

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `DEFAULT_EXPANSION_TIMEOUT` | `EP_DEFAULT_EXPANSION_TIMEOUT` | 5.0 | Default URL expansion timeout (seconds) |
| `EXPANSION_TIMEOUT_MIN` | `EP_EXPANSION_TIMEOUT_MIN` | 1.0 | Minimum URL expansion timeout |
| `EXPANSION_TIMEOUT_MAX` | `EP_EXPANSION_TIMEOUT_MAX` | 30.0 | Maximum URL expansion timeout |
| `EXPANSION_DELAY` | `EP_EXPANSION_DELAY` | 0.5 | Delay between URL expansions (seconds) |
| `FUNCTION_TIMEOUT_SECONDS` | `EP_FUNCTION_TIMEOUT_SECONDS` | 300 | Azure Function timeout (seconds) |

### Email Parsing Thresholds

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `EML_HEADER_CHECK_SIZE` | `EP_EML_HEADER_CHECK_SIZE` | 2048 | Bytes to check for EML headers |
| `HIGH_CONFIDENCE_HEADER_COUNT` | `EP_HIGH_CONFIDENCE_HEADER_COUNT` | 3 | Headers required for high confidence EML detection |
| `MEDIUM_CONFIDENCE_HEADER_COUNT` | `EP_MEDIUM_CONFIDENCE_HEADER_COUNT` | 2 | Headers required for medium confidence |
| `LOW_CONFIDENCE_HEADER_COUNT` | `EP_LOW_CONFIDENCE_HEADER_COUNT` | 1 | Headers required for low confidence |
| `MIN_HEADER_COUNT` | `EP_MIN_HEADER_COUNT` | 1 | Minimum headers to attempt parsing |

### MSG Parsing Configuration

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `BASE64_LINE_WRAP_LENGTH` | `EP_BASE64_LINE_WRAP_LENGTH` | 76 | Base64 line wrap length |
| `HEADER_PATTERN_CHECK_LINES` | `EP_HEADER_PATTERN_CHECK_LINES` | 10 | Lines to check for header patterns |
| `MIN_HEADER_PATTERNS` | `EP_MIN_HEADER_PATTERNS` | 2 | Minimum header patterns required |

### Proofpoint Detection Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `STRONG_PROOFPOINT_INDICATORS` | `EP_STRONG_PROOFPOINT_INDICATORS` | 2 | Strong indicators required |
| `EMAIL_CONTENT_INDICATORS` | `EP_EMAIL_CONTENT_INDICATORS` | 3 | Email content indicators required |
| `MIN_EMAIL_CONTENT_LENGTH` | `EP_MIN_EMAIL_CONTENT_LENGTH` | 200 | Minimum email content length |
| `MIN_SUBSTANTIAL_TEXT_LENGTH` | `EP_MIN_SUBSTANTIAL_TEXT_LENGTH` | 100 | Minimum substantial text length |
| `MIN_REASONABLE_CONTENT_LENGTH` | `EP_MIN_REASONABLE_CONTENT_LENGTH` | 50 | Minimum reasonable content length |
| `VALID_EMAIL_INDICATOR_COUNT` | `EP_VALID_EMAIL_INDICATOR_COUNT` | 3 | Valid email indicators required |
| `FALLBACK_CONTENT_MIN_LENGTH` | `EP_FALLBACK_CONTENT_MIN_LENGTH` | 200 | Fallback content minimum length |
| `MIN_HEADERS_LENGTH` | `EP_MIN_HEADERS_LENGTH` | 20 | Minimum headers length |
| `PATTERN_COUNT_IN_CONTENT` | `EP_PATTERN_COUNT_IN_CONTENT` | 2 | Pattern count in content |
| `PROOFPOINT_CONTENT_MIN` | `EP_PROOFPOINT_CONTENT_MIN` | 200 | Proofpoint content minimum |

### Content Analysis Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `MAGIC_BYTE_CHECK_SIZE` | `EP_MAGIC_BYTE_CHECK_SIZE` | 16 | Bytes to check for magic signatures |
| `MSG_FILE_SAMPLE_CHECK_SIZE` | `EP_MSG_FILE_SAMPLE_CHECK_SIZE` | 8192 | Sample size for MSG file checks |
| `ASCII_RATIO_CHECK_SIZE` | `EP_ASCII_RATIO_CHECK_SIZE` | 1024 | Bytes to check for ASCII ratio |
| `ENTROPY_CALCULATION_SIZE` | `EP_ENTROPY_CALCULATION_SIZE` | 4096 | Bytes to use for entropy calculation |

### Document Processing Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `MEANINGFUL_CONTENT_LIMIT` | `EP_MEANINGFUL_CONTENT_LIMIT` | 10 | Meaningful content items limit |
| `MEANINGFUL_LINES_LIMIT` | `EP_MEANINGFUL_LINES_LIMIT` | 5 | Meaningful lines limit |

### Debug and Preview Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `DEBUG_PREVIEW_CHARS` | `EP_DEBUG_PREVIEW_CHARS` | 500 | Characters to show in debug content previews |
| `HTML_PREVIEW_CHARS` | `EP_HTML_PREVIEW_CHARS` | 50 | Characters to show in HTML content previews |

### URL Analysis Settings

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `SHORT_URL_PATH_LENGTH` | `EP_SHORT_URL_PATH_LENGTH` | 10 | Path length for short URL detection |
| `SEPARATOR_LINE_MIN_LENGTH` | `EP_SEPARATOR_LINE_MIN_LENGTH` | 5 | Minimum separator line length |

### Feature Flags

| Setting | Environment Variable | Default | Description |
|---------|---------------------|---------|-------------|
| `DEFAULT_ENABLE_URL_ANALYSIS` | `EP_DEFAULT_ENABLE_URL_ANALYSIS` | true | Enable URL analysis by default |
| `DEFAULT_ENABLE_URL_EXPANSION` | `EP_DEFAULT_ENABLE_URL_EXPANSION` | false | Enable URL expansion by default |
| `DEFAULT_ENABLE_DOCUMENT_PROCESSING` | `EP_DEFAULT_ENABLE_DOCUMENT_PROCESSING` | true | Enable document processing by default |
| `DEFAULT_SHOW_DOCUMENT_TEXT` | `EP_DEFAULT_SHOW_DOCUMENT_TEXT` | false | Show document text by default |
| `DEFAULT_VERBOSE` | `EP_DEFAULT_VERBOSE` | false | Enable verbose logging by default |
| `DEFAULT_LOG_LEVEL` | `EP_DEFAULT_LOG_LEVEL` | INFO | Default log level |

## Static Configuration Lists

### Supported Content Types
- `text/plain`
- `application/octet-stream`
- `application/json`
- `multipart/form-data`

### Dangerous File Extensions
- `.exe`, `.bat`, `.cmd`, `.scr`, `.pif`

### Image File Extensions
- `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.svg`, `.webp`, `.tiff`

### URL Shortener Domains
39 domains including: `bit.ly`, `t.co`, `goo.gl`, `tinyurl.com`, `ow.ly`, `is.gd`, `buff.ly`, etc.

### XML Schema URL Filters
- `http://schemas.`
- `http://www.w3.org/`
- `http://purl.org/`
- `http://ns.adobe.com/`

### Proofpoint Markers
- `---------- Begin Email Headers ----------`
- `---------- Begin Reported Email ----------`
- `---------- Begin Attachment`
- `---------- End Email Headers ----------`
- `---------- End Reported Email ----------`
- `---------- End Attachment`
- `X-Proofpoint`
- `X-PFPT`
- `Proofpoint Protection`

### Proofpoint Subject Indicators
- `[EXTERNAL]`
- `[SUSPICIOUS]`
- `[CAUTION]`
- `FW: [EXTERNAL]`
- `Fwd: [EXTERNAL]`
- `PHISHING`
- `SUSPECTED`
- `REPORTED`

## Usage Examples

### Environment Variables
```bash
# Increase file size limit to 100MB
export EP_MAX_FILE_SIZE_MB=100

# Adjust URL expansion timeout
export EP_DEFAULT_EXPANSION_TIMEOUT=10.0

# Enable verbose logging by default
export EP_DEFAULT_VERBOSE=true

# Adjust document processing limits
export EP_DOCUMENT_TEXT_LIMIT=50000

# Adjust debug preview length
export EP_DEBUG_PREVIEW_CHARS=1000

# Adjust HTML preview length
export EP_HTML_PREVIEW_CHARS=100
```

### Programmatic Access
```python
from shared.config import config

# Access configuration values
print(f"Max file size: {config.MAX_FILE_SIZE_MB} MB")
print(f"URL shorteners: {len(config.URL_SHORTENERS)}")

# Get all configuration as dictionary
config_dict = config.get_config_dict()
```

### Azure Function App Settings
In your Azure Function App, set these as Application Settings:
```
EP_MAX_FILE_SIZE_MB = 100
EP_DEFAULT_EXPANSION_TIMEOUT = 10.0
EP_DEFAULT_ENABLE_URL_EXPANSION = true
```

## Migration Notes

### What Changed
- All hardcoded values moved to `shared/config.py`
- Environment variable support added for all settings
- Consistent naming convention applied
- Property-based access for dynamic lists
- Improved error messages for document extraction failures (now mentions when documents likely contain images)

### Backward Compatibility
- All existing functionality preserved
- Default values match previous hardcoded values
- No breaking changes to public APIs

### Performance Impact
- Minimal: Configuration loaded once at startup
- Property-based access for lists has negligible overhead
- Environment variable parsing happens at initialization

## Troubleshooting

### Common Issues
1. **Configuration not loading**: Check import path `from shared.config import config`
2. **Environment variables not working**: Ensure proper `EP_` prefix
3. **Type errors**: Environment variables are strings, ensure proper casting in config.py

### Debugging
```python
from shared.config import config
import os

# Check if environment variable is set
print(f"EP_MAX_FILE_SIZE_MB: {os.getenv('EP_MAX_FILE_SIZE_MB')}")

# Check actual config value
print(f"Actual max size: {config.MAX_FILE_SIZE_MB}")

# Get full configuration
config_dict = config.get_config_dict()
for key, value in config_dict.items():
    print(f"{key}: {value}")
```

## Best Practices

1. **Use environment variables for deployment-specific settings**
2. **Keep sensitive values in environment variables, not config files**
3. **Document any custom environment variables you set**
4. **Test configuration changes in development first**
5. **Use the `get_config_dict()` method for debugging**

## Future Enhancements

Planned improvements:
- JSON configuration file support
- Configuration validation
- Runtime configuration updates
- Configuration profiles (dev/prod)
- Web UI for configuration management