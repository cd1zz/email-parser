#!/usr/bin/env python3
import json
import sys
from pathlib import Path
sys.path.append('../../function-app')
from email_parser import create_email_parser

def analyze_structure(email_file):
    parser = create_email_parser(
        enable_url_analysis=True,
        enable_document_processing=True
    )
    
    with open(email_file, 'rb') as f:
        email_data = f.read()
    
    # Parse with no verbose logging
    result = parser.parse(email_data, Path(email_file).name, verbose=False)
    
    # Print clean JSON
    print(json.dumps(result, indent=2, default=str))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_structure.py <email_file>")
        sys.exit(1)
    
    analyze_structure(sys.argv[1])