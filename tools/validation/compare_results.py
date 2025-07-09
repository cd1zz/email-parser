#!/usr/bin/env python3
import json
import sys
from pathlib import Path
sys.path.append('../../function-app')
from email_parser import create_email_parser

def test_pair(email_num):
    print(f"\n=== Email {email_num} Comparison ===")
    
    parser = create_email_parser(
        enable_url_analysis=True,
        enable_document_processing=True
    )
    
    for ext in ['eml', 'msg']:
        email_file = f"{email_num}.{ext}"
        try:
            with open(f"../../test_emails/{email_file}", 'rb') as f:
                email_data = f.read()
            
            result = parser.parse(email_data, email_file, verbose=False)
            
            if result.get("status") == "success":
                structure = result.get("structure", {})
                email = structure.get("email", {})
                attachments = email.get("attachments", [])
                nested_emails = email.get("nested_emails", [])
                urls = email.get("urls", [])
                
                print(f"  .{ext} format:")
                print(f"    Attachments: {len(attachments)}")
                print(f"    Nested emails: {len(nested_emails)}")
                print(f"    URLs: {len(urls)}")
                
                for i, att in enumerate(attachments):
                    print(f"      Attachment {i}: {att.get('size')} bytes ({att.get('type')})")
                    if att.get('contains_email'):
                        print(f"        Contains nested email: YES")
                    else:
                        print(f"        Contains nested email: NO")
                
                if urls:
                    print(f"    URLs found: {urls}")
                    
            else:
                print(f"  .{ext} format: ERROR - {result.get('status')}")
                
        except Exception as e:
            print(f"  .{ext} format: EXCEPTION - {e}")

# Test problematic emails
test_pair("3")
test_pair("4")
test_pair("5")

# Test one working pair as control
test_pair("1")