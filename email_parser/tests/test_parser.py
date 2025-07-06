import logging

import email_parser.parser as ep


def test_magic_byte_detection():
    detector = ep.EmailFormatDetector(logging.getLogger("test"))
    assert detector.detect_by_magic_bytes(b"Return-Path:") == "eml"


def test_parse_simple_eml(tmp_path):
    sample = b"From: a@b\n\nbody"
    result = ep.EmailParser().parse(sample, "sample.eml")
    assert result["status"] == "success"
