# Email Parser

This repository contains two related implementations of an advanced email parsing library.
The code can be run locally as a command line tool or deployed as an Azure
Functions application.

## Repository layout

- **`standalone/`** – Python package and CLI for local usage.  The `email_parser`
  package here includes the core parsing logic, document processing and
  diagnostics tools.
- **`function-app/`** – Azure Functions HTTP application.  It exposes the same
  parser through `/email-parse`, `/health` and `/config` endpoints and includes
  helper modules under `shared/`.

## Standalone CLI usage

The standalone package exposes a rich command line interface.  After installing
its dependencies you can parse an email file like this:

```bash
python -m email_parser.cli path/to/email.eml
```

Document text extraction and URL parsing from attachments are enabled by default.
Use `--no-document-processing` to disable that behaviour.  See `python -m
email_parser.cli --help` for all options.

## Function app usage

The Azure Functions version is defined in `function-app/function_app.py`.  To run
it locally, install `azure-functions` and the other dependencies from
`function-app/requirements.txt` and start the Azure Functions host.  The app
provides three HTTP routes:

- `POST /email-parse` – parse an email payload and return structured JSON
- `GET /health` – environment and dependency checks
- `GET /config` – show default configuration and environment details

## Development

Please read `AGENTS.md` for detailed coding and testing guidelines.  All new
changes should follow the security first approach and run the programmatic
checks described there.
