#!/usr/bin/env python3
"""Debug script to test pdfminer availability in the exact same way the function does."""

import sys
import logging

def test_pdfminer_import():
    """Test pdfminer import exactly like the health check does."""
    print(f"Python version: {sys.version}")
    print(f"Python executable: {sys.executable}")
    print(f"Python path: {sys.path}")
    print()
    
    # Test the exact same import pattern used in the health check
    try:
        from pdfminer.high_level import extract_text
        print("✓ SUCCESS: pdfminer.high_level.extract_text imported successfully")
        
        # Test actual extraction on a small PDF
        import io
        # Create a minimal PDF for testing
        test_data = b'%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n>>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n0000000120 00000 n \ntrailer\n<<\n/Size 4\n/Root 1 0 R\n>>\nstartxref\n193\n%%EOF'
        
        try:
            text = extract_text(io.BytesIO(test_data))
            print(f"✓ SUCCESS: PDF extraction test completed, result: '{text.strip()}'")
        except Exception as e:
            print(f"⚠ WARNING: PDF extraction failed: {e}")
        
        return True
        
    except ImportError as e:
        print(f"✗ FAILED: pdfminer import failed: {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: Unexpected error: {e}")
        return False

def test_document_extractor():
    """Test the document extractor class directly."""
    print("\n" + "="*50)
    print("Testing DocumentTextExtractor directly")
    print("="*50)
    
    try:
        # Import the exact same way the function does
        from email_parser.extractors.document_extractor import DocumentTextExtractor
        
        logger = logging.getLogger(__name__)
        extractor = DocumentTextExtractor(logger)
        
        print("✓ DocumentTextExtractor imported successfully")
        
        # Test the _extract_pdf_text method directly
        test_pdf_data = b'%PDF-1.4\ntest pdf content'  # Minimal test data
        result = extractor._extract_pdf_text(test_pdf_data)
        
        print(f"✓ PDF extraction method called")
        print(f"  Success: {result.success}")
        print(f"  Error: {result.error_message}")
        print(f"  Document type: {result.document_type}")
        
        return result.success
        
    except ImportError as e:
        print(f"✗ FAILED: DocumentTextExtractor import failed: {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: DocumentTextExtractor test failed: {e}")
        return False

if __name__ == "__main__":
    print("PDF Miner Debug Test")
    print("="*50)
    
    # Test 1: Direct import like health check
    pdfminer_works = test_pdfminer_import()
    
    # Test 2: Document extractor
    extractor_works = test_document_extractor()
    
    print("\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    print(f"Direct pdfminer import: {'✓ WORKS' if pdfminer_works else '✗ FAILED'}")
    print(f"Document extractor: {'✓ WORKS' if extractor_works else '✗ FAILED'}")
    
    if pdfminer_works and not extractor_works:
        print("\n🔍 DIAGNOSIS: pdfminer imports fine, but DocumentTextExtractor has an issue")
    elif not pdfminer_works:
        print("\n🔍 DIAGNOSIS: pdfminer import is failing")
    else:
        print("\n🔍 DIAGNOSIS: Everything should be working!")