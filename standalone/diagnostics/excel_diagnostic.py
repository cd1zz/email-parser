#!/usr/bin/env python3
"""
Comprehensive Excel text and URL extractor that finds content in all parts of the Excel file.
This addresses the issue where pandas only reads worksheet data but misses URLs in:
- Relationship files (_rels/*.xml.rels)
- Drawing files (xl/drawings/*.xml)
- Embedded objects and hyperlinks
- Comments and metadata
"""

import io
import logging
import zipfile
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Set
from dataclasses import dataclass


@dataclass
class ExcelExtractionResult:
    """Result of comprehensive Excel extraction."""
    text_content: str = ""
    urls_found: List[str] = None
    success: bool = False
    error_message: str = ""
    extraction_method: str = ""
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.urls_found is None:
            self.urls_found = []
        if self.metadata is None:
            self.metadata = {}


class ComprehensiveExcelExtractor:
    """
    Comprehensive Excel extractor that finds text and URLs in all parts of the Excel file.
    """
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
        # URL patterns to find in all content
        self.url_patterns = [
            r'https?://[^\s<>"{}|\\^`\[\]\']+',  # Standard HTTP/HTTPS URLs
            r'ftp://[^\s<>"{}|\\^`\[\]\']+',     # FTP URLs
            r'www\.[^\s<>"{}|\\^`\[\]\']+',      # www URLs without protocol
        ]
        
        # XML namespaces commonly used in Excel files
        self.namespaces = {
            'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
            'worksheet': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
            'drawing': 'http://schemas.openxmlformats.org/drawingml/2006/main',
            'xdr': 'http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing',
        }
    
    def extract_excel_comprehensive(self, excel_data: bytes, filename: str = None) -> ExcelExtractionResult:
        """
        Comprehensive extraction that finds text and URLs from all parts of Excel file.
        """
        if not excel_data:
            return ExcelExtractionResult(
                success=False,
                error_message="No Excel data provided"
            )
        
        self.logger.info(f"Starting comprehensive Excel extraction for {filename}")
        
        result = ExcelExtractionResult()
        all_text_content = []
        all_urls = set()
        
        try:
            # Method 1: Try pandas first for worksheet data
            pandas_text = self._extract_with_pandas(excel_data)
            if pandas_text and pandas_text.strip():
                all_text_content.append("=== WORKSHEET DATA (pandas) ===")
                all_text_content.append(pandas_text)
                all_text_content.append("")
                self.logger.info("✓ Extracted worksheet data with pandas")
            
            # Method 2: Comprehensive ZIP-based extraction
            zip_text, zip_urls = self._extract_from_zip_structure(excel_data)
            if zip_text:
                all_text_content.append(zip_text)
                all_text_content.append("")
                self.logger.info("✓ Extracted additional content from ZIP structure")
            
            all_urls.update(zip_urls)
            
            # Method 3: Raw text search for any missed URLs
            raw_urls = self._extract_urls_from_raw_data(excel_data)
            all_urls.update(raw_urls)
            
            # Compile results
            final_text = "\n".join(all_text_content).strip()
            final_urls = self._clean_and_deduplicate_urls(list(all_urls))
            
            if final_text or final_urls:
                result.text_content = final_text if final_text else "[No text content extracted]"
                result.urls_found = final_urls
                result.success = True
                result.extraction_method = "comprehensive_multi_method"
                result.metadata = {
                    'text_length': len(final_text),
                    'urls_count': len(final_urls),
                    'methods_used': ['pandas', 'zip_analysis', 'raw_search']
                }
                self.logger.info(f"✓ Comprehensive extraction successful: {len(final_text)} chars, {len(final_urls)} URLs")
            else:
                result.success = False
                result.error_message = "No content found with any extraction method"
                self.logger.warning("No content found with any extraction method")
                
        except Exception as e:
            result.success = False
            result.error_message = f"Comprehensive extraction failed: {str(e)}"
            self.logger.error(f"Comprehensive extraction failed: {e}")
        
        return result
    
    def _extract_with_pandas(self, excel_data: bytes) -> str:
        """Extract worksheet data using pandas."""
        try:
            import pandas as pd
            
            excel_file = io.BytesIO(excel_data)
            
            # Try multiple pandas approaches
            approaches = [
                {"engine": "openpyxl"},
                {"engine": "openpyxl", "header": None},
                {"engine": "openpyxl", "skiprows": 0, "header": None},
            ]
            
            for approach in approaches:
                try:
                    excel_file.seek(0)
                    dfs = pd.read_excel(excel_file, sheet_name=None, **approach)
                    
                    text_parts = []
                    for sheet_name, df in dfs.items():
                        if not df.empty:
                            text_parts.append(f"Sheet: {sheet_name}")
                            text_parts.append(df.fillna('').to_string(index=False))
                            text_parts.append("")
                    
                    if text_parts:
                        return "\n".join(text_parts)
                        
                except Exception as e:
                    self.logger.debug(f"Pandas approach {approach} failed: {e}")
                    continue
            
            return ""
            
        except ImportError:
            self.logger.debug("pandas not available")
            return ""
        except Exception as e:
            self.logger.debug(f"Pandas extraction failed: {e}")
            return ""
    
    def _extract_from_zip_structure(self, excel_data: bytes) -> tuple[str, Set[str]]:
        """Extract content and URLs from all files in the Excel ZIP structure."""
        try:
            excel_file = io.BytesIO(excel_data)
            text_parts = []
            urls_found = set()
            
            with zipfile.ZipFile(excel_file, 'r') as zip_file:
                # Files to analyze for content and URLs
                files_to_check = [
                    # Relationship files (where external links are stored)
                    '_rels/.rels',
                    'xl/_rels/workbook.xml.rels',
                    'xl/worksheets/_rels/sheet1.xml.rels',
                    'xl/drawings/_rels/drawing1.xml.rels',
                    
                    # Drawing files (where embedded objects and hyperlinks are)
                    'xl/drawings/drawing1.xml',
                    
                    # Worksheet files (main data)
                    'xl/worksheets/sheet1.xml',
                    
                    # Comments and other content
                    'xl/comments1.xml',
                    'xl/sharedStrings.xml',
                    
                    # Metadata
                    'docProps/core.xml',
                    'docProps/app.xml',
                ]
                
                # Also check any file that exists in the ZIP
                available_files = zip_file.namelist()
                
                # Add any additional relationship or drawing files
                for file_path in available_files:
                    if (file_path.endswith('.rels') or 
                        'drawings' in file_path or 
                        'worksheets' in file_path or
                        'comments' in file_path):
                        if file_path not in files_to_check:
                            files_to_check.append(file_path)
                
                self.logger.info(f"Analyzing {len(files_to_check)} files in Excel ZIP structure")
                
                for file_path in files_to_check:
                    if file_path in available_files:
                        try:
                            content = zip_file.read(file_path)
                            
                            # Try to decode as text
                            try:
                                text_content = content.decode('utf-8')
                            except UnicodeDecodeError:
                                text_content = content.decode('latin-1', errors='ignore')
                            
                            # Extract URLs from this file
                            file_urls = self._extract_urls_from_text(text_content)
                            if file_urls:
                                urls_found.update(file_urls)
                                self.logger.info(f"Found {len(file_urls)} URLs in {file_path}: {file_urls}")
                            
                            # Extract meaningful text content (not just XML schema URLs)
                            meaningful_text = self._extract_meaningful_text_from_xml(text_content, file_path)
                            if meaningful_text:
                                text_parts.append(f"=== {file_path} ===")
                                text_parts.append(meaningful_text)
                                text_parts.append("")
                            
                        except Exception as e:
                            self.logger.debug(f"Error processing {file_path}: {e}")
                            continue
            
            return "\n".join(text_parts), urls_found
            
        except Exception as e:
            self.logger.error(f"ZIP structure analysis failed: {e}")
            return "", set()
    
    def _extract_urls_from_raw_data(self, excel_data: bytes) -> Set[str]:
        """Extract URLs from raw binary data as last resort."""
        try:
            # Convert to text for URL searching
            try:
                text_data = excel_data.decode('utf-8', errors='ignore')
            except:
                text_data = excel_data.decode('latin-1', errors='ignore')
            
            urls = self._extract_urls_from_text(text_data)
            if urls:
                self.logger.info(f"Found {len(urls)} URLs in raw data search")
            
            return set(urls)
            
        except Exception as e:
            self.logger.debug(f"Raw data URL extraction failed: {e}")
            return set()
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """Extract all URLs from text using multiple patterns."""
        urls = []
        
        for pattern in self.url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(matches)
        
        return urls
    
    def _extract_meaningful_text_from_xml(self, xml_content: str, file_path: str) -> str:
        """Extract meaningful text from XML, filtering out schema URLs."""
        try:
            # Parse as XML to extract meaningful content
            root = ET.fromstring(xml_content)
            
            meaningful_content = []
            
            # Look for text content in various elements
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    text = elem.text.strip()
                    
                    # Skip XML schema URLs and namespaces
                    if not (text.startswith('http://schemas.') or 
                           text.startswith('http://www.w3.org/') or
                           text.startswith('http://purl.org/') or
                           len(text) < 3):
                        meaningful_content.append(text)
                
                # Also check attributes for meaningful content
                for attr_name, attr_value in elem.attrib.items():
                    if attr_value and not attr_value.startswith('http://schemas.'):
                        # Look for URLs or meaningful text in attributes
                        if ('http://' in attr_value or 'https://' in attr_value or 
                            'www.' in attr_value or len(attr_value) > 10):
                            meaningful_content.append(f"{attr_name}: {attr_value}")
            
            if meaningful_content:
                return "\n".join(meaningful_content[:20])  # Limit output
            
        except ET.ParseError:
            # If not valid XML, do simple text extraction
            lines = xml_content.split('\n')
            meaningful_lines = []
            
            for line in lines:
                line = line.strip()
                if (line and 
                    not line.startswith('<?xml') and 
                    not line.startswith('<') and
                    not line.startswith('http://schemas.') and
                    len(line) > 5):
                    meaningful_lines.append(line)
            
            if meaningful_lines:
                return "\n".join(meaningful_lines[:10])  # Limit output
        
        except Exception as e:
            self.logger.debug(f"Error extracting meaningful text from {file_path}: {e}")
        
        return ""
    
    def _clean_and_deduplicate_urls(self, urls: List[str]) -> List[str]:
        """Clean and deduplicate URLs, filtering out XML schema URLs."""
        cleaned_urls = []
        seen_urls = set()
        
        for url in urls:
            # Clean the URL
            url = url.strip().rstrip('",\'>')
            
            # Skip XML schema URLs and other noise
            if (url.startswith('http://schemas.') or 
                url.startswith('http://www.w3.org/') or 
                url.startswith('http://purl.org/') or
                url.startswith('http://ns.adobe.com/') or
                len(url) < 10):
                continue
            
            # Normalize for deduplication
            url_normalized = url.lower()
            if url_normalized not in seen_urls:
                seen_urls.add(url_normalized)
                cleaned_urls.append(url)
        
        return cleaned_urls


# Test function
def test_comprehensive_extraction():
    """Test the comprehensive extraction on the problematic Excel file."""
    import logging
    from email import parser as email_parser
    from email import policy as email_policy
    
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    
    email_path = "../test_emails/excel_example.eml"
    
    try:
        # Read and parse email
        with open(email_path, 'rb') as f:
            email_data = f.read()
        
        parser = email_parser.BytesParser(policy=email_policy.default)
        message = parser.parsebytes(email_data)
        
        # Find Excel attachment
        if message.is_multipart():
            for part in message.get_payload():
                content_type = part.get_content_type()
                filename = part.get_filename()
                
                if (content_type == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' or
                    (filename and filename.lower().endswith('.xlsx'))):
                    
                    print(f"Testing comprehensive extraction on: {filename}")
                    
                    attachment_data = part.get_payload(decode=True)
                    if attachment_data:
                        extractor = ComprehensiveExcelExtractor(logger)
                        result = extractor.extract_excel_comprehensive(attachment_data, filename)
                        
                        print(f"\nResults:")
                        print(f"Success: {result.success}")
                        if result.success:
                            print(f"Text length: {len(result.text_content)}")
                            print(f"URLs found: {result.urls_found}")
                            print(f"Extraction method: {result.extraction_method}")
                            print(f"Metadata: {result.metadata}")
                            
                            if result.text_content:
                                print(f"\nText preview (first 500 chars):")
                                print(result.text_content[:500] + "..." if len(result.text_content) > 500 else result.text_content)
                        else:
                            print(f"Error: {result.error_message}")
                        
                        return
        
        print("No Excel attachment found")
        
    except Exception as e:
        print(f"Test failed: {e}")


if __name__ == "__main__":
    test_comprehensive_extraction()