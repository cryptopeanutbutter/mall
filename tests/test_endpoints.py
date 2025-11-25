import base64
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))

from analysis_core import (
    DISCORD_WEBHOOK_RE,
    GENERIC_URL_RE,
    IPV4_RE,
    TELEGRAM_RE,
    extract_strings,
    find_endpoints,
)


def test_extract_strings_ascii_and_utf16():
    data = b"hello\x00w\x00e\x00b\x00h\x00o\x00o\x00k\x00" + b" random" + b"URL"
    strings = extract_strings(data)
    assert any(s.startswith("hello") for s in strings)
    assert any("webhook" in s for s in strings)


def test_discord_webhook_regex_matches():
    sample = "https://discord.com/api/webhooks/123456789012345/" + ("a" * 24)
    assert DISCORD_WEBHOOK_RE.search(sample)


def test_generic_url_and_ip_regex():
    url = "https://example.com/path"
    ip = "192.168.0.1"
    assert GENERIC_URL_RE.search(url)
    assert IPV4_RE.search(ip)


def test_telegram_regex():
    endpoint = "https://api.telegram.org/botABC123/sendMessage"
    assert TELEGRAM_RE.search(endpoint)


def test_endpoint_confidence_levels():
    strings = [
        "contains https://discord.com/api/webhooks/12345/" + ("b" * 25),
        "api/webhooks suspicious http://example.com",
        "generic http://example.org",
    ]
    endpoints = find_endpoints(strings)
    webhook = endpoints["Discord Webhooks"][0]
    assert webhook["confidence"] == "High"
    other_urls = endpoints["Other URLs"]
    assert any(e["confidence"] == "Medium" for e in other_urls)
    assert any(e["confidence"] == "Low" for e in other_urls)


def test_base64_decoding_surfaces_webhook():
    raw_webhook = "https://discord.com/api/webhooks/123456789012345/" + ("c" * 24)
    encoded = base64.b64encode(raw_webhook.encode()).decode()
    endpoints = find_endpoints([encoded])
    webhook = endpoints["Discord Webhooks"][0]
    assert webhook["value"] == raw_webhook
    assert webhook.get("source") == "decoded (base64)"
