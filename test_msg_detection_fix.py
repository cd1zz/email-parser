#!/usr/bin/env python3
"""
Test script to demonstrate the MSG file type detection fix.

This script shows how the enhanced OLE compound document detection
correctly identifies MSG files vs DOC/XLS files.
"""

import sys
import os
import logging

# Add the function-app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'function-app'))

from email_parser.content_analyzer import ContentAnalyzer

def create_test_data():
    """Create test data simulating different OLE compound document types."""
    
    # OLE compound document header (shared by MSG, DOC, XLS)
    ole_header = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 504
    
    # Simulate MSG file content
    msg_content = ole_header + b'''
    \x00\x00\x1f\x00subject content
    \x00\x00\x0c\x00from sender
    \x00\x00\x1a\x00to recipient
    __properties_version1.0
    __recip_version1.0
    __attach_version1.0
    \x1f\x00\x1e\x00mapi properties
    '''.replace(b'\n    ', b'')
    
    # Simulate DOC file content  
    doc_content = ole_header + b'''
    Microsoft Office Word
    Word.Document
    WordDocument stream
    Word 97 document
    '''.replace(b'\n    ', b'')
    
    # Simulate XLS file content
    xls_content = ole_header + b'''
    Microsoft Office Excel
    Worksheet data
    Workbook stream
    Excel document
    Biff format
    '''.replace(b'\n    ', b'')
    
    return {
        'msg_content': msg_content,
        'doc_content': doc_content, 
        'xls_content': xls_content
    }

def test_ole_detection():
    """Test the OLE compound document detection logic."""
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    # Create content analyzer
    analyzer = ContentAnalyzer(logger)
    
    # Create test data
    test_data = create_test_data()
    
    print("=" * 80)
    print("MSG FILE TYPE DETECTION TEST")
    print("=" * 80)
    
    test_cases = [
        ("MSG file with .msg filename", test_data['msg_content'], "test.msg"),
        ("MSG file without filename", test_data['msg_content'], None),
        ("DOC file with .doc filename", test_data['doc_content'], "test.doc"),
        ("DOC file without filename", test_data['doc_content'], None),
        ("XLS file with .xls filename", test_data['xls_content'], "test.xls"),
        ("XLS file without filename", test_data['xls_content'], None),
        ("MSG content with wrong extension", test_data['msg_content'], "test.doc"),
        ("DOC content with wrong extension", test_data['doc_content'], "test.msg"),
    ]
    
    results = []
    
    for description, content, filename in test_cases:
        print(f"\nTesting: {description}")
        print(f"Filename: {filename}")
        print(f"Content size: {len(content)} bytes")
        
        # Analyze content
        analysis = analyzer.analyze_content(content, filename)
        
        print(f"Detected type: {analysis.detected_type}")
        print(f"MIME type: {analysis.mime_type}")
        print(f"Confidence: {analysis.confidence:.2f}")
        
        results.append({
            'description': description,
            'filename': filename,
            'detected_type': analysis.detected_type,
            'mime_type': analysis.mime_type,
            'confidence': analysis.confidence,
            'expected_correct': _is_detection_correct(description, analysis.detected_type)
        })
        
        if analysis.error:
            print(f"Error: {analysis.error}")
    
    print("\n" + "=" * 80)
    print("SUMMARY OF RESULTS")
    print("=" * 80)
    
    correct_count = 0
    total_count = len(results)
    
    for result in results:
        status = "✅ CORRECT" if result['expected_correct'] else "❌ INCORRECT"
        print(f"{status}: {result['description']}")
        print(f"   Detected: {result['detected_type']} (confidence: {result['confidence']:.2f})")
        
        if result['expected_correct']:
            correct_count += 1
    
    print(f"\nAccuracy: {correct_count}/{total_count} ({100*correct_count/total_count:.1f}%)")
    
    return results

def _is_detection_correct(description: str, detected_type: str) -> bool:
    """Check if the detection result is correct based on the test description."""
    if "MSG file" in description or "MSG content" in description:
        return detected_type == "msg"
    elif "DOC file" in description or "DOC content" in description:
        return detected_type == "doc"  
    elif "XLS file" in description:
        return detected_type == "xls"
    return False

if __name__ == "__main__":
    print("Testing MSG file type detection fix...")
    results = test_ole_detection()
    print(f"\n" + "=" * 80)
    print("This fix resolves the bug where nested binary MSG files")
    print("were incorrectly identified as DOC files.")