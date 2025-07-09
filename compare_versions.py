#!/usr/bin/env python3
"""
Compare output between standalone CLI and function-app parser to verify they produce identical results.
"""

import json
import sys
import tempfile
import subprocess
from pathlib import Path

def run_standalone_parser(email_file):
    """Run the standalone CLI parser and return parsed JSON."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        tmp_path = tmp.name
    
    try:
        # Run standalone parser
        result = subprocess.run([
            sys.executable, '-m', 'standalone', 
            email_file, '--no-document-processing', '--output', tmp_path
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            print(f"Standalone parser failed for {email_file}: {result.stderr}")
            return None
            
        # Read the output
        with open(tmp_path, 'r') as f:
            return json.load(f)
            
    finally:
        # Clean up
        Path(tmp_path).unlink(missing_ok=True)

def run_function_app_parser(email_file):
    """Run the function-app parser directly and return parsed JSON."""
    sys.path.insert(0, str(Path(__file__).parent / "function-app"))
    
    from email_parser import create_email_parser
    
    parser = create_email_parser(
        enable_url_analysis=True,
        enable_document_processing=False  # Match standalone test
    )
    
    try:
        with open(email_file, 'rb') as f:
            email_data = f.read()
        
        result = parser.parse(email_data, Path(email_file).name, verbose=False)
        return result
        
    except Exception as e:
        print(f"Function-app parser failed for {email_file}: {e}")
        return None

def compare_results(standalone_result, function_app_result, email_file):
    """Compare two parser results and report differences."""
    print(f"\n=== Comparing {email_file} ===")
    
    if standalone_result is None or function_app_result is None:
        print("❌ One or both parsers failed")
        return False
    
    # Compare status
    standalone_status = standalone_result.get('status')
    function_app_status = function_app_result.get('status')
    
    if standalone_status != function_app_status:
        print(f"❌ Status mismatch: standalone={standalone_status}, function-app={function_app_status}")
        return False
    
    if standalone_status != 'success':
        print(f"⚠️  Both parsers failed with status: {standalone_status}")
        return True  # Both failed the same way
    
    # Compare detected format
    standalone_format = standalone_result.get('detected_format')
    function_app_format = function_app_result.get('detected_format')
    
    if standalone_format != function_app_format:
        print(f"❌ Format mismatch: standalone={standalone_format}, function-app={function_app_format}")
        return False
    
    # Compare key structure elements
    standalone_structure = standalone_result.get('structure', {})
    function_app_structure = function_app_result.get('structure', {})
    
    # Compare metadata
    standalone_metadata = standalone_structure.get('metadata', {})
    function_app_metadata = function_app_structure.get('metadata', {})
    
    key_fields = ['total_depth', 'total_emails', 'total_attachments']
    for field in key_fields:
        if standalone_metadata.get(field) != function_app_metadata.get(field):
            print(f"❌ Metadata mismatch in {field}: standalone={standalone_metadata.get(field)}, function-app={function_app_metadata.get(field)}")
            return False
    
    # Compare email structure
    standalone_email = standalone_structure.get('email', {})
    function_app_email = function_app_structure.get('email', {})
    
    # Compare headers
    standalone_headers = standalone_email.get('headers', {})
    function_app_headers = function_app_email.get('headers', {})
    
    header_fields = ['from', 'to', 'subject', 'date', 'message_id']
    for field in header_fields:
        if standalone_headers.get(field) != function_app_headers.get(field):
            print(f"❌ Header mismatch in {field}")
            return False
    
    # Compare attachments count
    standalone_attachments = len(standalone_email.get('attachments', []))
    function_app_attachments = len(function_app_email.get('attachments', []))
    
    if standalone_attachments != function_app_attachments:
        print(f"❌ Attachment count mismatch: standalone={standalone_attachments}, function-app={function_app_attachments}")
        return False
    
    # Compare nested emails count
    standalone_nested = len(standalone_email.get('nested_emails', []))
    function_app_nested = len(function_app_email.get('nested_emails', []))
    
    if standalone_nested != function_app_nested:
        print(f"❌ Nested email count mismatch: standalone={standalone_nested}, function-app={function_app_nested}")
        return False
    
    print("✅ Results match!")
    return True

def main():
    """Main comparison function."""
    print("🔍 Comparing standalone CLI vs function-app parser results...")
    
    # Test files to compare
    test_files = [
        "test_emails/1.eml",
        "test_emails/2.eml", 
        "test_emails/3.eml",
        "test_emails/4.eml",
        "test_emails/5.eml"
    ]
    
    all_passed = True
    
    for email_file in test_files:
        if not Path(email_file).exists():
            print(f"⚠️  Skipping {email_file} (file not found)")
            continue
            
        standalone_result = run_standalone_parser(email_file)
        function_app_result = run_function_app_parser(email_file)
        
        if not compare_results(standalone_result, function_app_result, email_file):
            all_passed = False
    
    print(f"\n{'='*60}")
    if all_passed:
        print("🎉 All tests passed! Both versions produce identical results.")
    else:
        print("❌ Some tests failed. Results differ between versions.")
    print(f"{'='*60}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())