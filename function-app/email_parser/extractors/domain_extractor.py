# ============================================================================
# email_parser/extractors/domain_extractor.py
# ============================================================================
"""Domain extraction utilities for email parsing."""

import logging
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class DomainExtractionResult:
    """Result container for extracted domains."""

    domains: List[str] = field(default_factory=list)
    domain_count: int = 0


class DomainExtractor:
    """Extract domain names from text content."""

    DOMAIN_PATTERN = re.compile(
        r"(?:[a-zA-Z0-9-]{1,63}\.)+(?:[a-zA-Z]{2,63})"
    )

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def extract_domains_from_text(self, text: str) -> DomainExtractionResult:
        """Extract unique domain names from the given text."""
        if not text:
            return DomainExtractionResult()

        matches = self.DOMAIN_PATTERN.findall(text)
        seen = set()
        domains = []
        for match in matches:
            domain = match.lower().strip('.')
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)

        self.logger.debug(
            "Extracted %d domains from text (%d chars)",
            len(domains),
            len(text),
        )
        return DomainExtractionResult(domains=domains, domain_count=len(domains))