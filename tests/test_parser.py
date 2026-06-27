import pytest
from parser import parse_line, parse_file

SAMPLE = '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /login HTTP/1.1" 401 1234'

def test_extracts_ip():
    assert parse_line(SAMPLE).ip == "83.149.9.216"

def test_extracts_status():
    assert parse_line(SAMPLE).status == "401"

def test_extracts_path():
    assert parse_line(SAMPLE).path == "/login"

def test_returns_none_for_empty():
    assert parse_line("") is None
    assert parse_line("   ") is None

def test_returns_none_for_garbage():
    assert parse_line("this is not a log line") is None

def test_raises_for_missing_file():
    with pytest.raises(FileNotFoundError):
        parse_file("does_not_exist.log")
