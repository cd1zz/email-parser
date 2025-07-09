#!/usr/bin/env python3
import json
import logging
import sys
from pathlib import Path
sys.path.append('../../function-app')
from email_parser import create_email_parser

# Disable logging for cleaner output
logging.disable(logging.CRITICAL)

def validate_structure_improvements():
    """Validate that the new structure improvements are working correctly."""
    
    print("🔍 VALIDATION: New Structure Implementation")
    print("=" * 60)
    
    test_files = [
        "../../test_emails/1.msg",
        "../../test_emails/3.msg", 
        "../../test_emails/5.msg"
    ]
    
    parser = create_email_parser(
        enable_url_analysis=True,
        enable_document_processing=True
    )
    
    for test_file in test_files:
        print(f"\n📧 Testing: {Path(test_file).name}")
        
        try:
            with open(test_file, 'rb') as f:
                email_data = f.read()
            
            result = parser.parse(email_data, Path(test_file).name, verbose=False)
            
            if result.get("status") != "success":
                print(f"❌ Failed to parse {test_file}")
                continue
                
            structure = result.get("structure", {})
            email = structure.get("email", {})
            summary = structure.get("summary", {})
            
            # Check for duplication elimination
            print("  ✅ Checking duplication elimination...")
            
            # Count attachments with nested email references vs full objects
            attachments = email.get("attachments", [])
            email_attachments = [att for att in attachments if att.get("contains_email")]
            
            reference_count = 0
            full_object_count = 0
            
            for att in email_attachments:
                if "nested_email_id" in att:
                    reference_count += 1
                if "nested_email" in att:
                    full_object_count += 1
            
            print(f"    Email attachments: {len(email_attachments)}")
            print(f"    Using references: {reference_count}")
            print(f"    Using full objects: {full_object_count}")
            
            if full_object_count > 0:
                print("    ❌ ERROR: Still found full nested email objects!")
            else:
                print("    ✅ SUCCESS: All email attachments use references")
            
            # Check nested email IDs
            nested_emails = email.get("nested_emails", [])
            print(f"  ✅ Checking nested email IDs...")
            print(f"    Nested emails: {len(nested_emails)}")
            
            for i, nested in enumerate(nested_emails):
                nested_id = nested.get("id")
                if nested_id:
                    print(f"    [{i}] ID: {nested_id}")
                else:
                    print(f"    [{i}] ❌ ERROR: Missing ID")
            
            # Check enhanced summary
            print(f"  ✅ Checking enhanced summary...")
            urls_info = summary.get("urls", {})
            domains_info = summary.get("domains", {})
            
            print(f"    URLs: {urls_info.get('total_count', 0)} unique")
            print(f"    Domains: {domains_info.get('total_count', 0)} unique")
            print(f"    Shortened URLs: {len(urls_info.get('shortened_urls', []))}")
            print(f"    External domains: {len(domains_info.get('external_domains', []))}")
            
            # Check JSON size
            json_size = len(json.dumps(result))
            print(f"  📏 JSON size: {json_size:,} characters")
            
            # Validate structure completeness
            print(f"  ✅ Checking structure completeness...")
            
            required_fields = ["level", "headers", "body", "attachments", "nested_emails", "urls"]
            for field in required_fields:
                if field in email:
                    print(f"    ✅ {field}: present")
                else:
                    print(f"    ❌ {field}: missing")
            
            # Check nested email completeness
            for i, nested in enumerate(nested_emails):
                missing_fields = [field for field in required_fields if field not in nested]
                if missing_fields:
                    print(f"    ❌ Nested email {i} missing: {missing_fields}")
                else:
                    print(f"    ✅ Nested email {i}: complete")
            
        except Exception as e:
            print(f"❌ Error testing {test_file}: {e}")
    
    print("\n🎯 VALIDATION COMPLETE")
    print("=" * 60)
    
    # Test both formats for consistency
    print("\n📊 FORMAT CONSISTENCY TEST")
    print("=" * 60)
    
    format_pairs = [
        ("../test_emails/1.eml", "../test_emails/1.msg"),
        ("../test_emails/3.eml", "../test_emails/3.msg"),
        ("../test_emails/5.eml", "../test_emails/5.msg")
    ]
    
    for eml_file, msg_file in format_pairs:
        print(f"\n📧 Comparing: {Path(eml_file).name} vs {Path(msg_file).name}")
        
        try:
            # Parse both formats
            results = {}
            for file_path in [eml_file, msg_file]:
                with open(file_path, 'rb') as f:
                    email_data = f.read()
                
                result = parser.parse(email_data, Path(file_path).name, verbose=False)
                results[Path(file_path).suffix] = result
            
            # Compare key metrics
            for ext in ['.eml', '.msg']:
                if ext in results and results[ext].get("status") == "success":
                    structure = results[ext].get("structure", {})
                    summary = structure.get("summary", {})
                    
                    print(f"  {ext.upper()}:")
                    print(f"    Total emails: {summary.get('total_emails', 0)}")
                    print(f"    Total attachments: {summary.get('total_attachments', 0)}")
                    print(f"    Unique URLs: {summary.get('urls', {}).get('total_count', 0)}")
                    print(f"    Unique domains: {summary.get('domains', {}).get('total_count', 0)}")
                    print(f"    JSON size: {len(json.dumps(results[ext])):,} chars")
                else:
                    print(f"  {ext.upper()}: ❌ Failed to parse")
            
        except Exception as e:
            print(f"❌ Error comparing formats: {e}")
    
    print("\n✅ ALL VALIDATIONS COMPLETE")

if __name__ == "__main__":
    validate_structure_improvements()