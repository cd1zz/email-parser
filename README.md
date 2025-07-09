# Email Parser

An advanced Python email parsing library designed for cybersecurity applications, email forensics, and automated analysis workflows. Supports multiple email formats with comprehensive nested email parsing, document text extraction, URL analysis, and Proofpoint detection capabilities.

## Features

### Core Capabilities
- **Multi-format Support**: EML, MSG, MBOX files with automatic format detection
- **Nested Email Parsing**: Recursive parsing of embedded messages with unique ID assignment
- **Document Processing**: Text extraction from PDF, Word, Excel attachments with URL detection
- **Proofpoint Detection**: Automatic unwrapping of Proofpoint-wrapped security emails
- **URL Analysis**: Comprehensive URL extraction, expansion, and domain categorization
- **Content Validation**: MIME type detection and content type mismatch identification
- **Structured Output**: Clean JSON with deduplication and summary sections

### Advanced Features
- **Excel URL Extraction**: Comprehensive ZIP analysis for relationship files (OneDrive links)
- **Base64 Email Detection**: Automatic detection and decoding of base64-encoded nested emails
- **Content Type Validation**: Detects mismatches between declared and actual content types
- **Security-First Design**: Input validation, content scanning, and size limits
- **Dual Deployment**: Identical core parsing logic for CLI and serverless environments
- **Feature Parity**: Both deployment modes offer the same parsing capabilities and output formats

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/cd1zz/email-parser
cd email-parser

# Set up virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r function-app/requirements.txt
```

### Basic Usage

```bash
# Parse an email file
python -m email_parser.cli test_emails/1.eml

# Parse with verbose output
python -m email_parser.cli test_emails/1.msg --verbose

# Parse with URL analysis enabled
python -m email_parser.cli test_emails/1.eml --enable-url-analysis

# Save results to file
python -m email_parser.cli test_emails/1.eml --output results.json
```

### Programmatic Usage

```python
from email_parser import create_email_parser

# Create parser with full feature set
parser = create_email_parser(
    enable_url_analysis=True,
    enable_document_processing=True,
    enable_url_expansion=True
)

# Parse email file
with open('email.msg', 'rb') as f:
    result = parser.parse(f.read(), 'email.msg')

# Access structured results
if result['status'] == 'success':
    structure = result['structure']
    email_data = structure['email']
    summary = structure['summary']
    
    print(f"Found {len(email_data['nested_emails'])} nested emails")
    print(f"Total URLs: {summary['urls']['total_count']}")
    print(f"Unique domains: {summary['domains']['unique_count']}")
```

## Repository Structure

- **`function-app/`** – Azure Functions serverless deployment with HTTP endpoints
- **`standalone/`** – Local CLI implementation with diagnostic tools
- **`test_emails/`** – 50+ test files including EML/MSG pairs and edge cases
- **`tools/`** – Development utilities including debug scripts and validation tools

**Note:** Both `function-app` and `standalone` versions contain identical core parsing functionality. The function-app version adds HTTP endpoints and web service utilities, while the standalone version includes diagnostic tools. Users can choose either deployment method with confidence that the email parsing capabilities are identical.

## CLI Commands

### Basic Parsing
```bash
# Parse email with default settings
python -m email_parser.cli email.eml

# Parse MSG file with verbose output
python -m email_parser.cli email.msg --verbose

# Disable document processing for speed
python -m email_parser.cli email.eml --no-document-processing
```

### Advanced Options
```bash
# Enable URL expansion and analysis
python -m email_parser.cli email.eml --enable-url-analysis --enable-url-expansion

# Process with custom output format
python -m email_parser.cli email.eml --output analysis.json --format json

# Debug mode with maximum logging
python -m email_parser.cli email.eml --verbose --debug
```

### Diagnostic Tools
```bash
# Analyze MSG file structure
python standalone/diagnostics/msg_diagnostic.py test_emails/1.msg

# Analyze Excel file for URLs
python standalone/diagnostics/excel_diagnostic.py test_emails/sample.xlsx

# Test Proofpoint detection
python standalone/diagnostics/proofpoint_diagnostic.py test_emails/proofpoint_sample.eml
```

## Azure Functions Deployment

### Local Development
```bash
# Install Azure Functions Core Tools
npm install -g azure-functions-core-tools@4

# Start local development server
cd function-app
func start
```

### HTTP Endpoints
```bash
# Health check
curl http://localhost:7071/health

# Configuration details
curl http://localhost:7071/config

# Parse email (multipart/form-data)
curl -X POST http://localhost:7071/email-parse \
  -F "file=@test_emails/1.eml"
```

### Production Deployment
```bash
# Deploy to Azure
az functionapp deployment source config-zip \
  --resource-group myResourceGroup \
  --name myFunctionApp \
  --src function-app.zip
```

## Testing

### Running Tests
```bash
# Run comprehensive test suite
python tools/testing/test_all_fixes.py

# Test nested email parsing
python tools/testing/test_msg_nested_fix.py

# Test attachment processing
python tools/testing/test_attachment_fix.py

# Test with specific email types
python -m email_parser.cli test_emails/nested_msgs.eml --verbose
python -m email_parser.cli test_emails/excel_example.eml --verbose
```

### Test Email Collection
The project includes 50+ test files covering:
- **Format pairs**: EML/MSG versions of the same emails
- **Nested emails**: Complex forwarding chains and embedded messages
- **Attachments**: PDF, Word, Excel files with embedded URLs
- **Edge cases**: Proofpoint samples, spam detection, malformed content
- **Special cases**: Base64 encoded emails, content type mismatches

## Output Format

### Structured JSON Response
```json
{
  "status": "success",
  "structure": {
    "metadata": {
      "filename": "email.eml",
      "format": "eml",
      "processing_time": 1.23
    },
    "email": {
      "level": 0,
      "headers": {...},
      "body": {
        "text": "Email body content",
        "html": "HTML content"
      },
      "attachments": [...],
      "nested_emails": [
        {
          "id": "nested_0_0",
          "depth": 1,
          "headers": {...},
          "body": {...}
        }
      ]
    },
    "summary": {
      "total_emails": 3,
      "total_attachments": 2,
      "urls": {
        "total_count": 5,
        "unique_domain_count": 3
      },
      "domains": {
        "unique_count": 3,
        "list": ["example.com", "microsoft.com"]
      }
    }
  }
}
```

## Dependencies

### Core Requirements
- **Python 3.10+** (3.8+ supported)
- **azure-functions>=1.11.0** - Azure Functions runtime
- **extract-msg>=0.28.0** - MSG file parsing
- **pandas>=2.0.3** - Data processing
- **requests>=2.25.0** - URL analysis

### Document Processing
- **pdfminer.six==20211012** - PDF text extraction
- **python-docx>=0.8.11** - Word document processing
- **openpyxl==3.1.2** - Excel file analysis
- **html2text>=2020.1.16** - HTML to text conversion

### Optional Dependencies
- **textract** - Alternative document processing
- **xlrd** - Legacy Excel file support

## Security Considerations

- **Input Validation**: Robust validation of email content and attachments
- **Content Scanning**: Detection of potentially malicious content
- **Size Limits**: Configurable limits for file and attachment sizes
- **URL Validation**: Safety checks for URL processing
- **Proofpoint Integration**: Proper handling of security-wrapped emails

## Performance Optimization

- **Streaming Processing**: Handle large attachments efficiently
- **Selective Processing**: Disable features for speed when needed
- **Memory Management**: Efficient handling of nested email chains
- **Caching**: Intelligent caching for repeated operations

## Troubleshooting

### Common Issues
1. **pdfminer DLL Issues**: Install via conda or use alternative PDF processing
2. **MSG Format Errors**: Ensure extract-msg library is properly installed
3. **Unicode Handling**: Check content normalizer for encoding issues
4. **Memory Usage**: Large attachments may require streaming processing

### Debug Commands
```bash
# Environment validation
python -c "from email_parser import create_email_parser; print('OK')"

# Library compatibility check
python function-app/shared/environment_validator.py

# Test specific functionality
python debug_nested_structure.py
python debug_url_extraction.py
```

## Development Guidelines

### Code Quality
- Follow PEP 8 style guidelines
- Use type hints for all functions
- Implement comprehensive error handling
- Write detailed docstrings
- Maintain backward compatibility

### Testing Requirements
- Test with real-world email samples
- Cover edge cases and malformed content
- Validate performance with large attachments
- Ensure EML/MSG pairs produce consistent results

### Security Standards
- Validate all inputs thoroughly
- Handle potentially malicious content safely
- Implement proper logging and monitoring
- Follow principle of least privilege

## Contributing

1. **Read Documentation**: Review `AGENTS.md` for detailed guidelines
2. **Run Tests**: Ensure all tests pass before submitting
3. **Security Review**: Consider security implications of changes
4. **Performance Testing**: Validate performance with large files
5. **Documentation**: Update documentation for new features

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For issues, feature requests, or questions:
- **GitHub Issues**: [https://github.com/cd1zz/email-parser/issues](https://github.com/cd1zz/email-parser/issues)
- **Documentation**: See `CLAUDE.md` for detailed implementation guide
- **Development**: See `AGENTS.md` for coding guidelines
