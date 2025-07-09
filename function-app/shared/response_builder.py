"""Response builder for Azure Function email parser."""

from datetime import datetime, timezone
from typing import Dict, Any


class ResponseBuilder:
    """Builds standardized HTTP responses for the email parser function."""
    
    @staticmethod
    def build_success_response(
        email_analysis: Dict[str, Any],
        request_id: str,
        execution_time_ms: int,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build a success response with email analysis results."""
        
        # Extract processing summary from email analysis
        processing_summary = ResponseBuilder._extract_processing_summary(email_analysis)
        
        return {
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": execution_time_ms,
            "request_id": request_id,
            "email_analysis": email_analysis,
            "metadata": {
                "function_version": "1.0.0",
                "parser_version": "2.1",
                "processing_summary": processing_summary,
                "configuration_used": {
                    "enable_url_analysis": config["enable_url_analysis"],
                    "enable_url_expansion": config["enable_url_expansion"],
                    "enable_document_processing": config["enable_document_processing"],
                    "verbose_output": config["verbose"]
                }
            }
        }
    
    @staticmethod
    def _extract_processing_summary(email_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Extract processing summary from email analysis results."""
        summary = {
            "documents_processed": 0,
            "urls_found": 0,
            "attachments_analyzed": 0,
            "nested_emails_found": 0
        }
        
        try:
            # Handle different output formats (verbose vs streamlined)
            if "structure" in email_analysis:
                # Verbose format
                structure = email_analysis["structure"]
                summary["attachments_analyzed"] = structure.get("attachment_count", 0)
                summary["nested_emails_found"] = structure.get("nested_email_count", 0)
                
                # Extract URL count from URL analysis
                if "url_analysis" in structure and structure["url_analysis"]:
                    url_summary = structure["url_analysis"].get("summary", {})
                    summary["urls_found"] = url_summary.get("total_urls", 0)
                    
            elif "email" in email_analysis:
                # Streamlined format
                email_obj = email_analysis["email"]
                summary["urls_found"] = len(email_obj.get("urls", []))
                summary["attachments_analyzed"] = len(email_obj.get("attachments", []))
                summary["nested_emails_found"] = len(email_obj.get("nested_emails", []))
                
                # Document processing summary
                doc_analysis = email_analysis.get("document_analysis", {})
                summary["documents_processed"] = doc_analysis.get("total_documents_processed", 0)
                
        except Exception:
            # If summary extraction fails, return defaults
            pass
            
        return summary