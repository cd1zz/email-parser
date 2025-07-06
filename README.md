# Email Parser

This project provides a small library for parsing `.eml` and `.msg` files with a simple command line interface.

## Usage

```bash
python -m email_parser.cli path/to/email.eml
```

Document text extraction and URL parsing from attachments are enabled by default.
Use `--no-document-processing` if you wish to disable this behavior.
