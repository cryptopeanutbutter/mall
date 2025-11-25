# StaticLens Webhook Finder

StaticLens Webhook Finder is a defensive desktop tool for malware responders to statically triage files and locate potential exfiltration endpoints (with a focus on Discord webhooks). The application **never executes samples** and only performs byte-level inspection.

## Features

- Drag-and-drop a file or folder for recursive scanning (200MB per file cap)
- Sidebar of scanned items; selecting an item shows its analysis
- Tabs for summary metadata, endpoints, strings, hex preview, and entrypoint disassembly
- Endpoint extractor detects Discord webhooks, generic URLs, IPv4 addresses, Telegram bot endpoints, and common paste/C2 hosts
- Confidence scoring (High/Medium/Low) for endpoints
- Export findings to JSON (path, metadata, endpoints, top strings)
- Progress feedback during folder scans via a worker thread (non-blocking UI)

## Safety constraints

- Static analysis only: no execution, emulation, or import of dropped files
- Treats all input as untrusted bytes
- If metadata cannot be determined statically, the UI reports it as unavailable

## Getting started

### Prerequisites
- Python 3.11+
- [Qt dependencies](https://doc.qt.io/qtforpython/gettingstarted.html) (PySide6 handles most platforms automatically)

### Installation
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

### Running the app
```bash
python main.py
```
Drag a suspicious file or folder onto the drop area to begin a scan. The left sidebar will populate with items; select one to view details.

### Running tests
```bash
pytest
```

### Building a standalone binary (PyInstaller)
```bash
pip install pyinstaller
pyinstaller --name StaticLens --onefile --windowed main.py
```
The resulting executable appears in the `dist/` directory.

## Project structure
- `main.py` — PySide6 GUI, drag-and-drop handling, worker thread, and views
- `analysis_core.py` — static metadata extraction, string harvesting, endpoint detection, export helper
- `tests/test_endpoints.py` — unit tests for string extraction and endpoint regexes
- `requirements.txt` — runtime and dev dependencies

## Notes
- Disassembly uses Capstone on the entrypoint bytes when available. If unavailable or unsupported architecture, the UI states this explicitly.
- Hex preview is limited to the first 512 bytes for quick inspection.

