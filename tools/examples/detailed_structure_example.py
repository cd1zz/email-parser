#!/usr/bin/env python3
import json

def create_detailed_structure_example():
    """Create a comprehensive example showing where body and URLs go at each layer"""
    
    # Example of a complex nested email structure
    example_structure = {
        "status": "success",
        "detected_format": "msg",
        "structure": {
            "metadata": {
                "parser_version": "2.1",
                "total_depth": 2,
                "total_emails": 3,
                "total_attachments": 6
            },
            "email": {
                "level": 0,
                "headers": {
                    "from": "Andre Samuels <asamuels@eidebailly.com>",
                    "to": "sharedphishingmailbox@pwnag3.com",
                    "subject": "FW: Phishing Email Analysis",
                    "date": "2025-05-16 11:14:46-06:00"
                },
                "body": {
                    "text": "Please review the attached phishing email. This was forwarded from our security team.",
                    "html": "<div>Please review the attached phishing email. This was forwarded from our security team.</div>",
                    "has_html": True
                },
                "urls": [
                    "https://security.microsoft.com/userSubmissionsReportMessage",
                    "https://internal-security-portal.company.com"
                ],
                "attachments": [
                    {
                        "name": "image001.png",
                        "type": "image",
                        "size": 424,
                        "contains_email": False,
                        "mime_type": "image/png"
                    },
                    {
                        "name": "phishing_email.eml",
                        "type": "email",
                        "size": 109216,
                        "contains_email": True,
                        "mime_type": "message/rfc822",
                        "nested_email_id": "nested_0"
                    }
                ],
                "nested_emails": [
                    {
                        "id": "nested_0",
                        "level": 1,
                        "source_attachment": "phishing_email.eml",
                        "source_attachment_index": 1,
                        "headers": {
                            "from": "Malicious Actor <noreply@phishing-site.com>",
                            "to": "victim@company.com",
                            "subject": "Urgent: Verify Your Account - Action Required",
                            "date": "2025-04-23 23:25:55+00:00"
                        },
                        "body": {
                            "text": "Your account will be suspended unless you verify immediately. Click the link below to verify your account: https://fake-bank-login.malicious.com/verify",
                            "html": "<html><body><p>Your account will be suspended unless you verify immediately.</p><p><a href='https://fake-bank-login.malicious.com/verify'>Click here to verify</a></p></body></html>",
                            "has_html": True
                        },
                        "urls": [
                            "https://fake-bank-login.malicious.com/verify",
                            "https://malicious-redirect.com/track?id=123"
                        ],
                        "attachments": [
                            {
                                "name": "invoice.pdf",
                                "type": "document",
                                "size": 45000,
                                "contains_email": False,
                                "mime_type": "application/pdf"
                            },
                            {
                                "name": "forwarded_complaint.eml",
                                "type": "email",
                                "size": 25000,
                                "contains_email": True,
                                "mime_type": "message/rfc822",
                                "nested_email_id": "nested_1"
                            }
                        ],
                        "nested_emails": [
                            {
                                "id": "nested_1",
                                "level": 2,
                                "source_attachment": "forwarded_complaint.eml",
                                "source_attachment_index": 1,
                                "headers": {
                                    "from": "Customer Service <support@legitimate-bank.com>",
                                    "to": "complaints@bank.com",
                                    "subject": "Customer Complaint - Account Access Issues",
                                    "date": "2025-04-20 10:30:00+00:00"
                                },
                                "body": {
                                    "text": "Customer reported inability to access account. Please investigate. Contact customer at their secure portal: https://secure.legitimate-bank.com/support",
                                    "html": "<p>Customer reported inability to access account. Please investigate.</p><p>Contact: <a href='https://secure.legitimate-bank.com/support'>secure portal</a></p>",
                                    "has_html": True
                                },
                                "urls": [
                                    "https://secure.legitimate-bank.com/support",
                                    "https://internal-ticket-system.bank.com/case/12345"
                                ],
                                "attachments": [
                                    {
                                        "name": "customer_screenshot.png",
                                        "type": "image",
                                        "size": 150000,
                                        "contains_email": False,
                                        "mime_type": "image/png"
                                    }
                                ],
                                "nested_emails": [],
                                "document_extracts": []
                            }
                        ],
                        "document_extracts": []
                    }
                ],
                "document_extracts": []
            },
            "summary": {
                "email_chain_length": 3,
                "domains_involved": [
                    "eidebailly.com",
                    "pwnag3.com", 
                    "phishing-site.com",
                    "malicious.com",
                    "legitimate-bank.com"
                ],
                "total_urls": 6,
                "shortened_urls": [
                    {
                        "original": "https://bit.ly/bank-verify",
                        "expanded": "https://example-bank.com/login/verify"
                    },
                    {
                        "original": "https://t.co/abc123",
                        "expanded": "https://twitter.com/example/status/123"
                    }
                ],
                "total_attachments": 6,
                "contains_external_domains": True
            }
        }
    }
    
    return example_structure

def explain_structure_layers():
    """Explain where body and URLs are located at each layer"""
    
    print("=== EMAIL BODY AND URL LOCATIONS BY LAYER ===\n")
    
    print("📧 LAYER 0 (Top-level/Root Email):")
    print("   Location: structure.email.body")
    print("   Content: Main forwarding email body")
    print("   URLs: structure.email.urls")
    print("   Example: 'Please review the attached phishing email...'")
    print("   URLs: ['https://security.microsoft.com/...', 'https://internal-portal.com']")
    print()
    
    print("📧 LAYER 1 (First Nested Email):")
    print("   Location: structure.email.nested_emails[0].body")
    print("   Content: The actual phishing email content")
    print("   URLs: structure.email.nested_emails[0].urls")
    print("   Example: 'Your account will be suspended unless you verify...'")
    print("   URLs: ['https://fake-bank-login.malicious.com/verify', 'https://malicious-redirect.com/...']")
    print()
    
    print("📧 LAYER 2 (Second Nested Email):")
    print("   Location: structure.email.nested_emails[0].nested_emails[0].body")
    print("   Content: Email nested within the phishing email")
    print("   URLs: structure.email.nested_emails[0].nested_emails[0].urls")
    print("   Example: 'Customer reported inability to access account...'")
    print("   URLs: ['https://secure.legitimate-bank.com/support', 'https://internal-ticket-system.bank.com/...']")
    print()
    
    print("🔗 ATTACHMENT RELATIONSHIPS:")
    print("   Layer 0 attachment → Points to nested_emails[0] via nested_email_id")
    print("   Layer 1 attachment → Points to nested_emails[0].nested_emails[0] via nested_email_id")
    print("   Each layer maintains its own attachments array")
    print()
    
    print("🌐 URL AGGREGATION:")
    print("   All URLs from all layers are also collected in:")
    print("   - structure.summary.total_urls (count)")
    print("   - structure.summary.shortened_urls (URL shortener links)")
    print("   - Individual layer URLs remain in their respective email.urls arrays")
    print()

def show_traversal_patterns():
    """Show how to traverse the structure for different use cases"""
    
    print("=== TRAVERSAL PATTERNS ===\n")
    
    print("🔍 FOR SOC ANALYSTS - Sequential Analysis:")
    print("1. Analyze main email: structure.email.body + structure.email.urls")
    print("2. Check attachments: structure.email.attachments[]")
    print("3. For email attachments: use nested_email_id to find in nested_emails[]")
    print("4. Analyze nested email: nested_emails[i].body + nested_emails[i].urls")
    print("5. Repeat for deeper nesting: nested_emails[i].nested_emails[]")
    print()
    
    print("🤖 FOR LLM PROCESSING - Recursive Analysis:")
    print("```python")
    print("def analyze_email_layer(email_obj):")
    print("    # Process this layer's content")
    print("    body = email_obj.get('body', {})")
    print("    urls = email_obj.get('urls', [])")
    print("    attachments = email_obj.get('attachments', [])")
    print("    ")
    print("    # Process nested emails recursively")
    print("    for nested in email_obj.get('nested_emails', []):")
    print("        analyze_email_layer(nested)")
    print("```")
    print()
    
    print("🎯 FOR URL ANALYSIS:")
    print("1. Quick overview: structure.summary.shortened_urls")
    print("2. Layer-by-layer context:")
    print("   - Main email URLs: structure.email.urls")
    print("   - Nested email URLs: structure.email.nested_emails[i].urls")
    print("   - Deep nested URLs: structure.email.nested_emails[i].nested_emails[j].urls")
    print()

if __name__ == "__main__":
    # Create and display the example structure
    example = create_detailed_structure_example()
    
    print("=== DETAILED STRUCTURE EXAMPLE ===")
    print(json.dumps(example, indent=2))
    print("\n" + "="*80 + "\n")
    
    # Explain the structure
    explain_structure_layers()
    print("="*80 + "\n")
    
    # Show traversal patterns
    show_traversal_patterns()