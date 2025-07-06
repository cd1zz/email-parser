#!/usr/bin/env python3
"""
MSG File Diagnostic Script
Comprehensive analysis of what extract_msg can extract from a MSG file
"""

import sys
import os
import json
import pprint

try:
    import extract_msg
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False
    print("ERROR: extract_msg not available. Install with: pip install extract-msg")
    sys.exit(1)

def safe_repr(obj, max_length=200):
    """Safely represent an object for printing, truncating if too long."""
    try:
        if obj is None:
            return "None"
        elif isinstance(obj, bytes):
            if len(obj) > max_length:
                return f"<bytes: length={len(obj)}, preview={obj[:50]!r}...>"
            return repr(obj)
        elif isinstance(obj, str):
            if len(obj) > max_length:
                return f"<string: length={len(obj)}, preview={obj[:50]!r}...>"
            return repr(obj)
        else:
            str_repr = str(obj)
            if len(str_repr) > max_length:
                return f"<{type(obj).__name__}: {str_repr[:max_length]}...>"
            return str_repr
    except Exception as e:
        return f"<Error representing object: {e}>"

def analyze_msg_object(msg, prefix="", max_depth=3, current_depth=0):
    """Recursively analyze all properties and methods of the MSG object."""
    if current_depth > max_depth:
        return {"_truncated": "Max depth reached"}
    
    analysis = {}
    
    # Get all attributes
    for attr_name in sorted(dir(msg)):
        if attr_name.startswith('_'):
            continue
            
        try:
            attr_value = getattr(msg, attr_name)
            
            # Skip methods and functions for now
            if callable(attr_value):
                if not attr_name.startswith('get') and attr_name not in ['save', 'close']:
                    continue
                else:
                    # For getter methods, try to call them
                    try:
                        if attr_name.startswith('get') and '(' in str(attr_value):
                            continue  # Skip methods that require parameters
                        result = attr_value() if callable(attr_value) else attr_value
                        analysis[f"{attr_name}()"] = safe_repr(result)
                    except Exception as e:
                        analysis[f"{attr_name}()"] = f"<Error calling method: {e}>"
                continue
            
            # For non-callable attributes
            if hasattr(attr_value, '__dict__') and current_depth < max_depth:
                # Recursively analyze objects
                analysis[attr_name] = analyze_msg_object(attr_value, f"{prefix}{attr_name}.", max_depth, current_depth + 1)
            else:
                analysis[attr_name] = safe_repr(attr_value)
                
        except Exception as e:
            analysis[attr_name] = f"<Error accessing attribute: {e}>"
    
    return analysis

def analyze_attachments(msg):
    """Analyze attachments in detail."""
    attachment_analysis = []
    
    try:
        if hasattr(msg, 'attachments') and msg.attachments:
            for i, attachment in enumerate(msg.attachments):
                att_info = {
                    "index": i,
                    "properties": analyze_msg_object(attachment, f"attachment_{i}.", max_depth=2)
                }
                
                # Try to get specific attachment properties
                for prop in ['longFilename', 'shortFilename', 'data', 'size']:
                    try:
                        value = getattr(attachment, prop, None)
                        if prop == 'data' and value:
                            att_info[prop] = f"<bytes: length={len(value)}, type_detected='{detect_content_type(value)}'>"
                        else:
                            att_info[prop] = safe_repr(value)
                    except Exception as e:
                        att_info[prop] = f"<Error: {e}>"
                
                attachment_analysis.append(att_info)
    except Exception as e:
        return {"error": f"Error analyzing attachments: {e}"}
    
    return attachment_analysis

def detect_content_type(data):
    """Simple content type detection based on magic bytes."""
    if not data or len(data) < 4:
        return "unknown"
    
    # Check for common file signatures
    signatures = {
        b'\x89PNG': 'PNG image',
        b'\xff\xd8\xff': 'JPEG image', 
        b'GIF8': 'GIF image',
        b'%PDF': 'PDF document',
        b'\xd0\xcf\x11\xe0': 'OLE/MSG document',
        b'PK\x03\x04': 'ZIP/Office document',
        b'From:': 'Email content',
        b'Received:': 'Email content',
        b'Return-Path:': 'Email content',
    }
    
    for signature, description in signatures.items():
        if data.startswith(signature):
            return description
    
    return "unknown"

def analyze_content_encoding(content):
    """Analyze the encoding of content."""
    if content is None:
        return {"status": "None"}
    
    analysis = {
        "type": type(content).__name__,
        "length": len(content) if hasattr(content, '__len__') else "unknown"
    }
    
    if isinstance(content, bytes):
        # Check for UTF-16 patterns
        if len(content) >= 4:
            if content[:2] == b'\xff\xfe' or content[:2] == b'\xfe\xff':
                analysis["utf16_bom"] = "detected"
            
            # Check for alternating null bytes (UTF-16LE ASCII pattern)
            null_count = sum(1 for i in range(1, min(20, len(content)), 2) if content[i] == 0)
            analysis["null_byte_pattern"] = f"{null_count}/10 in even positions"
        
        # Try different decodings
        encodings_tried = {}
        for encoding in ['utf-8', 'utf-16le', 'utf-16', 'windows-1252', 'latin-1']:
            try:
                decoded = content.decode(encoding)
                preview = decoded[:100].replace('\n', '\\n').replace('\r', '\\r')
                encodings_tried[encoding] = f"success: {preview!r}"
            except Exception as e:
                encodings_tried[encoding] = f"failed: {e}"
        
        analysis["encoding_attempts"] = encodings_tried
    
    elif isinstance(content, str):
        analysis["preview"] = content[:200].replace('\n', '\\n').replace('\r', '\\r')
        
        # Check for Unicode escape sequences
        if '\\u' in content[:100]:
            analysis["unicode_escapes"] = "detected"
    
    return analysis

def main():
    if len(sys.argv) != 2:
        print("Usage: python msg_diagnostic.py <msg_file>")
        sys.exit(1)
    
    msg_file = sys.argv[1]
    
    if not os.path.exists(msg_file):
        print(f"Error: File {msg_file} not found")
        sys.exit(1)
    
    print(f"Analyzing MSG file: {msg_file}")
    print("=" * 80)
    
    try:
        # Open the MSG file
        msg = extract_msg.Message(msg_file)
        
        print("\n1. BASIC MSG PROPERTIES")
        print("-" * 40)
        
        # Basic properties
        basic_props = ['sender', 'to', 'cc', 'subject', 'date', 'messageId']
        for prop in basic_props:
            try:
                value = getattr(msg, prop, None)
                print(f"{prop}: {safe_repr(value)}")
            except Exception as e:
                print(f"{prop}: <Error: {e}>")
        
        print("\n2. BODY CONTENT ANALYSIS")
        print("-" * 40)
        
        # Analyze body content
        print("Plain body analysis:")
        plain_analysis = analyze_content_encoding(getattr(msg, 'body', None))
        pprint.pprint(plain_analysis, width=120)
        
        print("\nHTML body analysis:")
        html_analysis = analyze_content_encoding(getattr(msg, 'htmlBody', None))
        pprint.pprint(html_analysis, width=120)
        
        print("\n3. ALL MSG OBJECT PROPERTIES")
        print("-" * 40)
        
        # Full property analysis
        full_analysis = analyze_msg_object(msg, max_depth=2)
        
        # Group properties by category
        content_props = {}
        meta_props = {}
        other_props = {}
        
        for key, value in full_analysis.items():
            if any(term in key.lower() for term in ['body', 'text', 'html', 'content', 'message']):
                content_props[key] = value
            elif any(term in key.lower() for term in ['date', 'time', 'id', 'header', 'sender', 'recipient']):
                meta_props[key] = value
            else:
                other_props[key] = value
        
        print("\nContent-related properties:")
        pprint.pprint(content_props, width=120)
        
        print("\nMetadata properties:")
        pprint.pprint(meta_props, width=120)
        
        print("\nOther properties:")
        pprint.pprint(other_props, width=120)
        
        print("\n4. ATTACHMENT ANALYSIS")
        print("-" * 40)
        
        attachment_analysis = analyze_attachments(msg)
        pprint.pprint(attachment_analysis, width=120)
        
        print("\n5. RAW PROPERTIES DUMP")
        print("-" * 40)
        
        # Check if there are any properties that might contain raw email data
        print("Looking for properties that might contain raw email data:")
        
        for attr_name in sorted(dir(msg)):
            if any(term in attr_name.lower() for term in ['raw', 'stream', 'data', 'property', 'original']):
                try:
                    value = getattr(msg, attr_name)
                    if not callable(value):
                        print(f"{attr_name}: {safe_repr(value, 100)}")
                except Exception as e:
                    print(f"{attr_name}: <Error: {e}>")
        
        # Check for internal properties that might be useful
        print("\nInternal/private properties (might contain useful data):")
        for attr_name in sorted(dir(msg)):
            if attr_name.startswith('_') and not attr_name.startswith('__'):
                try:
                    value = getattr(msg, attr_name)
                    if not callable(value):
                        print(f"{attr_name}: {safe_repr(value, 100)}")
                except Exception as e:
                    print(f"{attr_name}: <Error: {e}>")
        
        # Save full analysis to JSON file
        output_file = f"{msg_file}_diagnostic.json"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                diagnostic_data = {
                    "basic_properties": {prop: safe_repr(getattr(msg, prop, None)) for prop in basic_props},
                    "body_analysis": {
                        "plain_body": plain_analysis,
                        "html_body": html_analysis
                    },
                    "all_properties": full_analysis,
                    "attachments": attachment_analysis
                }
                json.dump(diagnostic_data, f, indent=2, ensure_ascii=False, default=str)
            print(f"\nFull diagnostic data saved to: {output_file}")
        except Exception as e:
            print(f"\nWarning: Could not save diagnostic data to JSON: {e}")
        
        # Close the MSG object
        if hasattr(msg, 'close'):
            msg.close()
        elif hasattr(msg, '__exit__'):
            msg.__exit__(None, None, None)
            
    except Exception as e:
        print(f"Error analyzing MSG file: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()