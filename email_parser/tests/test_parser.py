import logging

import email_parser.parser as ep


def test_magic_byte_detection():
    detector = ep.EmailFormatDetector(logging.getLogger("test"))
    assert detector.detect_by_magic_bytes(b"Return-Path:") == "eml"


def test_parse_simple_eml(tmp_path):
    sample = b"From: a@b\n\nbody"
    result = ep.EmailParser().parse(sample, "sample.eml")
    assert result["status"] == "success"


class _DummyMsg:
    def __init__(self, body=None):
        self.sender = "s@a"
        self.to = "t@b"
        self.subject = "subj"
        self.body = body


def test_convert_msg_handles_none_body():
    parser = ep.EmailParser()
    content = parser._convert_msg(_DummyMsg(None))
    assert "From: s@a" in content
    assert isinstance(content, str)
