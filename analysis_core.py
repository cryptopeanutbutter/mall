"""
Static analysis core for PharaohLens Webhook Finder.
Performs safe, non-executing inspection of files to extract metadata and potential exfiltration endpoints.
"""
from __future__ import annotations

import base64
import json
import re
from binascii import Error as BinasciiError
from pathlib import Path
from typing import Dict, List

try:
    import lief
except Exception:  # pragma: no cover - fallback handled at runtime
    lief = None

try:
    import pefile  # type: ignore
except Exception:  # pragma: no cover
    pefile = None

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
except Exception:  # pragma: no cover
    ELFFile = None

MIN_STRING_LENGTH = 4
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB

DISCORD_WEBHOOK_RE = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{5,}/[\w-]{20,}",
    re.IGNORECASE,
)
GENERIC_URL_RE = re.compile(r"https?://[^\s\"'>]{4,}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
TELEGRAM_RE = re.compile(r"https?://api\.telegram\.org/bot[\w-]+/[\w/]+", re.IGNORECASE)
PASTE_HOST_RE = re.compile(
    r"https?://(?:pastebin\.com|raw\.githubusercontent\.com|ipfs\.io|gateway\.pinata\.cloud|cdn\.discordapp\.com)/[^\s\"'>]+",
    re.IGNORECASE,
)
SUSPICIOUS_KEYWORDS = {"webhook", "discord", "token", "api/webhooks", "steal", "exfil", "upload"}


class AnalysisError(Exception):
    """Raised when a file cannot be safely analyzed."""


def extract_ascii_strings(data: bytes, min_length: int = MIN_STRING_LENGTH) -> List[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    return [match.decode("utf-8", errors="ignore") for match in pattern.findall(data)]


def extract_utf16le_strings(data: bytes, min_length: int = MIN_STRING_LENGTH) -> List[str]:
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_length)
    strings: List[str] = []
    for match in pattern.findall(data):
        try:
            strings.append(match.decode("utf-16le", errors="ignore"))
        except Exception:
            continue
    return strings


def extract_strings(data: bytes, max_items: int = 5000) -> List[str]:
    ascii_strings = extract_ascii_strings(data)
    utf16_strings = extract_utf16le_strings(data)
    combined = []
    seen = set()
    for s in ascii_strings + utf16_strings:
        if s in seen:
            continue
        seen.add(s)
        combined.append(s)
        if len(combined) >= max_items:
            break
    return combined


def _try_base64_decode(text: str) -> str | None:
    cleaned = text.strip()
    if len(cleaned) < 12 or len(cleaned) > 2048:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned):
        return None
    if len(cleaned) % 4 != 0:
        return None
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except (BinasciiError, ValueError):
        return None
    if not decoded:
        return None
    try:
        text_val = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if sum(1 for c in text_val if c.isprintable()) / max(len(text_val), 1) < 0.8:
        return None
    return text_val


def _try_hex_decode(text: str) -> str | None:
    cleaned = text.strip().replace(" ", "")
    if len(cleaned) < 16 or len(cleaned) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    try:
        decoded = bytes.fromhex(cleaned)
    except ValueError:
        return None
    if not decoded:
        return None
    try:
        text_val = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if sum(1 for c in text_val if c.isprintable()) / max(len(text_val), 1) < 0.8:
        return None
    return text_val


def enrich_with_decoded_strings(strings: List[str]) -> List[Dict[str, str]]:
    enriched: List[Dict[str, str]] = []
    for s in strings:
        enriched.append({"value": s, "source": "plain"})
        decoded = _try_base64_decode(s)
        if decoded and decoded not in (entry["value"] for entry in enriched):
            enriched.append({"value": decoded, "source": "decoded (base64)"})
        decoded_hex = _try_hex_decode(s)
        if decoded_hex and decoded_hex not in (entry["value"] for entry in enriched):
            enriched.append({"value": decoded_hex, "source": "decoded (hex)"})
    return enriched


def _confidence_for_endpoint(value: str, is_webhook: bool = False, has_keyword: bool = False) -> str:
    if is_webhook:
        return "High"
    if has_keyword:
        return "Medium"
    return "Low"


def find_endpoints(strings: List[str]) -> Dict[str, List[Dict[str, str]]]:
    results: Dict[str, List[Dict[str, str]]] = {
        "Discord Webhooks": [],
        "Other URLs": [],
        "IPs": [],
        "Suspicious Keywords": [],
    }
    seen = set()

    enriched_strings = enrich_with_decoded_strings(strings)

    for item in enriched_strings:
        s = item["value"]
        source = item.get("source", "plain")
        has_keyword = any(keyword.lower() in s.lower() for keyword in SUSPICIOUS_KEYWORDS)

        for match in DISCORD_WEBHOOK_RE.findall(s):
            if match not in seen:
                seen.add(match)
                results["Discord Webhooks"].append({
                    "value": match,
                    "confidence": _confidence_for_endpoint(match, is_webhook=True),
                    "source": source,
                })

        for match in TELEGRAM_RE.findall(s):
            if match not in seen:
                seen.add(match)
                results["Other URLs"].append({
                    "value": match,
                    "confidence": _confidence_for_endpoint(match, has_keyword=has_keyword),
                    "source": source,
                })

        for match in PASTE_HOST_RE.findall(s):
            if match not in seen:
                seen.add(match)
                results["Other URLs"].append({
                    "value": match,
                    "confidence": _confidence_for_endpoint(match, has_keyword=has_keyword),
                    "source": source,
                })

        for match in GENERIC_URL_RE.findall(s):
            if match not in seen:
                seen.add(match)
                results["Other URLs"].append({
                    "value": match,
                    "confidence": _confidence_for_endpoint(match, has_keyword=has_keyword),
                    "source": source,
                })

        for match in IPV4_RE.findall(s):
            if match not in seen:
                seen.add(match)
                results["IPs"].append({
                    "value": match,
                    "confidence": _confidence_for_endpoint(match, has_keyword=has_keyword),
                    "source": source,
                })

        if has_keyword:
            results["Suspicious Keywords"].append({"value": s, "confidence": "Medium", "source": source})

    return results


def _lief_summary(binary) -> Dict[str, object]:  # pragma: no cover - exercised at runtime
    architecture = None
    try:
        architecture = str(getattr(binary.abstract, "architecture", None))
    except Exception:
        pass
    summary = {
        "format": getattr(binary, "format", None) and binary.format.name,
        "architecture": architecture,
        "entrypoint": getattr(binary, "entrypoint", None),
        "sections": [],
        "imports": [],
        "entrypoint_data": None,
    }
    try:
        for section in getattr(binary, "sections", []):
            summary["sections"].append({"name": section.name, "size": section.size})
    except Exception:
        pass
    try:
        for imp in getattr(binary, "imports", []):
            summary["imports"].append(imp.name)
    except Exception:
        pass
    try:
        entrypoint = getattr(binary, "entrypoint", None)
        if entrypoint:
            offset = binary.virtual_address_to_offset(entrypoint)
            size = 256
            ep_data = binary.get_content_from_virtual_address(entrypoint, size)
            summary["entrypoint_data"] = bytes(ep_data)
            summary["entrypoint_offset"] = offset
    except Exception:
        summary["entrypoint_data"] = None
    return summary


def _fallback_summary(path: Path) -> Dict[str, object]:
    summary = {
        "format": None,
        "architecture": None,
        "entrypoint": None,
        "sections": [],
        "imports": [],
        "entrypoint_data": None,
    }

    if pefile:
        try:
            pe = pefile.PE(str(path), fast_load=True)
            summary["format"] = "PE"
            summary["entrypoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            summary["architecture"] = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
            for section in pe.sections:
                summary["sections"].append({"name": section.Name.decode(errors="ignore").strip("\x00"), "size": section.SizeOfRawData})
        except Exception:
            pass

    if not summary["format"] and ELFFile:
        try:
            with path.open("rb") as f:
                elf = ELFFile(f)
                summary["format"] = "ELF"
                summary["architecture"] = str(elf['e_machine'])
                summary["entrypoint"] = elf.header.e_entry
                summary["sections"] = [{"name": sec.name, "size": sec.data_size} for sec in elf.iter_sections()]
        except Exception:
            pass

    return summary


def analyze_file(path: str | Path) -> Dict[str, object]:
    file_path = Path(path)
    if not file_path.exists():
        raise AnalysisError(f"File not found: {file_path}")
    if file_path.stat().st_size > MAX_FILE_SIZE:
        raise AnalysisError("File exceeds maximum allowed size for static scan (200MB)")

    data = file_path.read_bytes()

    summary: Dict[str, object]
    if lief:
        try:
            binary = lief.parse(list(data))  # type: ignore[arg-type]
            if binary:
                summary = _lief_summary(binary)
            else:
                summary = _fallback_summary(file_path)
        except Exception:
            summary = _fallback_summary(file_path)
    else:
        summary = _fallback_summary(file_path)

    strings = extract_strings(data)
    endpoints = find_endpoints(strings)

    # Keep top 200 strings for exporting
    top_strings = strings[:200]

    return {
        "path": str(file_path),
        "summary": summary,
        "endpoints": endpoints,
        "strings": top_strings,
    }


def export_findings(results: List[Dict[str, object]], destination: Path) -> None:
    export_payload = []
    for item in results:
        export_payload.append({
            "path": item.get("path"),
            "summary": item.get("summary", {}),
            "endpoints": item.get("endpoints", {}),
            "strings": item.get("strings", []),
        })
    destination.write_text(json.dumps(export_payload, indent=2))


__all__ = [
    "analyze_file",
    "export_findings",
    "find_endpoints",
    "extract_strings",
    "extract_ascii_strings",
    "extract_utf16le_strings",
    "enrich_with_decoded_strings",
    "DISCORD_WEBHOOK_RE",
    "GENERIC_URL_RE",
    "IPV4_RE",
    "TELEGRAM_RE",
    "AnalysisError",
]
