from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Dict, List

from PySide6 import QtCore, QtGui, QtWidgets

from analysis_core import AnalysisError, analyze_file, export_findings

try:
    import capstone
except Exception:  # pragma: no cover - fallback runtime
    capstone = None


class DropArea(QtWidgets.QLabel):
    fileDropped = QtCore.Signal(list)

    def __init__(self):
        super().__init__("Drop suspicious file or folder onto PharaohLens")
        self.setAlignment(QtCore.Qt.AlignCenter)
        self.setStyleSheet(
            """
            QLabel {
                border: 2px dashed #6c6c6c;
                border-radius: 8px;
                color: #555;
                font-size: 16px;
                padding: 24px;
            }
            """
        )
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QtGui.QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QtGui.QDropEvent):
        paths = []
        for url in event.mimeData().urls():
            paths.append(Path(url.toLocalFile()))
        if paths:
            self.fileDropped.emit(paths)


class AnalysisWorker(QtCore.QThread):
    fileAnalyzed = QtCore.Signal(dict)
    progressUpdated = QtCore.Signal(int, int)
    errorOccurred = QtCore.Signal(str)
    finishedScan = QtCore.Signal(int, int)

    def __init__(self, paths: List[Path]):
        super().__init__()
        self.paths = paths
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def _collect_files(self) -> List[Path]:
        files: List[Path] = []
        for path in self.paths:
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                for child in path.rglob("*"):
                    if child.is_file():
                        files.append(child)
        return files

    def run(self):
        files = self._collect_files()
        total = len(files)
        completed = 0
        webhook_files = 0
        unique_endpoints = set()

        for file_path in files:
            if self._stop_event.is_set():
                break
            try:
                result = analyze_file(file_path)
                # track endpoints
                if result.get("endpoints", {}).get("Discord Webhooks"):
                    webhook_files += 1
                for group in result.get("endpoints", {}).values():
                    for endpoint in group:
                        unique_endpoints.add(endpoint.get("value"))
                self.fileAnalyzed.emit(result)
            except AnalysisError as exc:
                self.errorOccurred.emit(str(exc))
            except Exception as exc:  # pragma: no cover - runtime safety
                self.errorOccurred.emit(f"Failed to analyze {file_path}: {exc}")
            completed += 1
            self.progressUpdated.emit(completed, total)

        self.finishedScan.emit(webhook_files, len(unique_endpoints))


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PharaohLens Webhook Finder")
        self.resize(1200, 800)
        self.results: Dict[str, dict] = {}

        container = QtWidgets.QWidget()
        self.setCentralWidget(container)

        main_layout = QtWidgets.QVBoxLayout(container)
        self.findings_label = QtWidgets.QLabel("Findings summary: waiting for input")
        main_layout.addWidget(self.findings_label)

        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)

        self.drop_area = DropArea()
        self.drop_area.fileDropped.connect(self.handle_drop)
        main_layout.addWidget(self.drop_area)

        body_layout = QtWidgets.QHBoxLayout()
        main_layout.addLayout(body_layout)

        sidebar_layout = QtWidgets.QVBoxLayout()
        body_layout.addLayout(sidebar_layout, 1)

        sidebar_title = QtWidgets.QLabel("Loaded Items")
        sidebar_title.setStyleSheet("font-weight: bold;")
        sidebar_layout.addWidget(sidebar_title)

        self.file_list = QtWidgets.QListWidget()
        self.file_list.itemSelectionChanged.connect(self.display_selected)
        sidebar_layout.addWidget(self.file_list, 1)

        self.export_button = QtWidgets.QPushButton("Export Findings")
        self.export_button.clicked.connect(self.export_findings)
        sidebar_layout.addWidget(self.export_button)

        self.tabs = QtWidgets.QTabWidget()
        body_layout.addWidget(self.tabs, 3)

        self.summary_view = QtWidgets.QTextEdit()
        self.summary_view.setReadOnly(True)
        self.tabs.addTab(self.summary_view, "Summary")

        # Endpoints tab
        endpoint_container = QtWidgets.QWidget()
        endpoint_layout = QtWidgets.QVBoxLayout(endpoint_container)
        search_layout = QtWidgets.QHBoxLayout()
        self.endpoint_search = QtWidgets.QLineEdit()
        self.endpoint_search.setPlaceholderText("Search endpoints")
        self.endpoint_search.textChanged.connect(self.filter_endpoints)
        self.copy_button = QtWidgets.QPushButton("Copy selected")
        self.copy_button.clicked.connect(self.copy_endpoint)
        search_layout.addWidget(self.endpoint_search)
        search_layout.addWidget(self.copy_button)
        endpoint_layout.addLayout(search_layout)

        self.endpoint_list = QtWidgets.QListWidget()
        self.endpoint_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.endpoint_list.customContextMenuRequested.connect(self.show_endpoint_menu)
        self.endpoint_list.itemDoubleClicked.connect(self.view_endpoint_details)
        endpoint_layout.addWidget(self.endpoint_list)
        self.tabs.addTab(endpoint_container, "Endpoints")

        # Strings tab
        strings_container = QtWidgets.QWidget()
        strings_layout = QtWidgets.QVBoxLayout(strings_container)
        self.string_search = QtWidgets.QLineEdit()
        self.string_search.setPlaceholderText("Search strings")
        self.string_search.textChanged.connect(self.filter_strings)
        strings_layout.addWidget(self.string_search)
        self.string_list = QtWidgets.QListWidget()
        strings_layout.addWidget(self.string_list)
        self.tabs.addTab(strings_container, "Strings")

        # Hex preview
        self.hex_view = QtWidgets.QPlainTextEdit()
        self.hex_view.setReadOnly(True)
        self.tabs.addTab(self.hex_view, "Hex Preview")

        # Disassembly
        self.disasm_view = QtWidgets.QPlainTextEdit()
        self.disasm_view.setReadOnly(True)
        self.tabs.addTab(self.disasm_view, "Disasm")

        self.worker: AnalysisWorker | None = None

    def handle_drop(self, paths: List[Path]):
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.warning(self, "Scan running", "Please wait for current scan to finish.")
            return

        self.results.clear()
        self.file_list.clear()
        self.endpoint_list.clear()
        self.string_list.clear()
        self.hex_view.clear()
        self.summary_view.clear()
        self.disasm_view.clear()
        self.findings_label.setText("Scanning...")
        self.progress_bar.show()
        self.progress_bar.setValue(0)

        self.worker = AnalysisWorker(paths)
        self.worker.fileAnalyzed.connect(self.add_result)
        self.worker.progressUpdated.connect(self.update_progress)
        self.worker.errorOccurred.connect(self.show_error)
        self.worker.finishedScan.connect(self.update_summary_counts)
        self.worker.start()

    def add_result(self, result: dict):
        self.results[result["path"]] = result
        item = QtWidgets.QListWidgetItem(result["path"])
        self.file_list.addItem(item)
        if self.file_list.count() == 1:
            self.file_list.setCurrentItem(item)

    def update_progress(self, completed: int, total: int):
        if total:
            self.progress_bar.setValue(int((completed / total) * 100))
        else:
            self.progress_bar.setValue(0)

    def update_summary_counts(self, webhook_files: int, unique_endpoints: int):
        self.progress_bar.hide()
        self.findings_label.setText(
            f"Files with Discord webhooks: {webhook_files} | Unique endpoints: {unique_endpoints}"
        )

    def show_error(self, message: str):
        QtWidgets.QMessageBox.warning(self, "Analysis error", message)

    def display_selected(self):
        items = self.file_list.selectedItems()
        if not items:
            return
        path = items[0].text()
        result = self.results.get(path)
        if not result:
            return
        self.populate_summary(result)
        self.populate_endpoints(result)
        self.populate_strings(result)
        self.populate_hex(result)
        self.populate_disasm(result)

    def populate_summary(self, result: dict):
        summary = result.get("summary", {})
        lines = [
            f"File: {result.get('path')}",
            f"Format: {summary.get('format') or 'Unknown'}",
            f"Architecture: {summary.get('architecture') or 'Unknown'}",
            f"Entrypoint: {summary.get('entrypoint') or 'Unknown'}",
            "Sections:",
        ]
        for section in summary.get("sections", []):
            lines.append(f"  - {section.get('name')}: {section.get('size')} bytes")
        lines.append("Imports:")
        for imp in summary.get("imports", []):
            lines.append(f"  - {imp}")
        self.summary_view.setPlainText("\n".join(lines))

    def populate_endpoints(self, result: dict):
        self.endpoint_list.clear()
        endpoints = result.get("endpoints", {})
        for group, values in endpoints.items():
            for entry in values:
                value = entry.get("value")
                confidence = entry.get("confidence", "Unknown")
                source = entry.get("source", "plain")
                entry_with_group = {**entry, "group": group}
                item = QtWidgets.QListWidgetItem(f"[{confidence}] {group} ({source}): {value}")
                item.setData(QtCore.Qt.UserRole, entry_with_group)
                self.endpoint_list.addItem(item)

    def filter_endpoints(self, text: str):
        for i in range(self.endpoint_list.count()):
            item = self.endpoint_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())

    def copy_endpoint(self):
        item = self.endpoint_list.currentItem()
        if not item:
            return
        entry = item.data(QtCore.Qt.UserRole) or {}
        QtWidgets.QApplication.clipboard().setText(entry.get("value", ""))

    def show_endpoint_menu(self, position: QtCore.QPoint):
        item = self.endpoint_list.itemAt(position)
        if not item:
            return
        self.endpoint_list.setCurrentItem(item)
        menu = QtWidgets.QMenu(self)
        copy_action = menu.addAction("Copy endpoint")
        view_action = menu.addAction("View details")
        action = menu.exec(self.endpoint_list.mapToGlobal(position))
        if action == copy_action:
            self.copy_endpoint()
        elif action == view_action:
            self.view_endpoint_details(item)

    def view_endpoint_details(self, item: QtWidgets.QListWidgetItem):
        entry = item.data(QtCore.Qt.UserRole) or {}
        lines = [
            f"Value: {entry.get('value', '')}",
            f"Group: {entry.get('group', 'Unknown')}",
            f"Confidence: {entry.get('confidence', 'Unknown')}",
            f"Source: {entry.get('source', 'plain')}",
        ]
        QtWidgets.QMessageBox.information(self, "Endpoint details", "\n".join(lines))

    def populate_strings(self, result: dict):
        self.string_list.clear()
        for s in result.get("strings", []):
            self.string_list.addItem(s)

    def filter_strings(self, text: str):
        for i in range(self.string_list.count()):
            item = self.string_list.item(i)
            item.setHidden(text.lower() not in item.text().lower())

    def populate_hex(self, result: dict):
        try:
            data = Path(result["path"]).read_bytes()[:512]
            hex_lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_chunk = " ".join(f"{b:02x}" for b in chunk)
                ascii_chunk = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_lines.append(f"{i:08x}  {hex_chunk:<47}  {ascii_chunk}")
            self.hex_view.setPlainText("\n".join(hex_lines))
        except Exception as exc:
            self.hex_view.setPlainText(f"Unable to display hex preview: {exc}")

    def populate_disasm(self, result: dict):
        summary = result.get("summary", {})
        entry_data = summary.get("entrypoint_data")
        if not capstone or not entry_data:
            self.disasm_view.setPlainText("Disassembly unavailable (no capstone or missing entrypoint data).")
            return

        arch_text = str(summary.get("architecture"))
        if "x86" in arch_text or "I386" in arch_text:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if "32" in arch_text else capstone.CS_MODE_64)
        elif "ARM64" in arch_text or "AARCH64" in arch_text:
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif "ARM" in arch_text:
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        else:
            self.disasm_view.setPlainText("Disassembly unavailable for this architecture.")
            return

        dis_lines = []
        for insn in md.disasm(entry_data, 0):
            dis_lines.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        self.disasm_view.setPlainText("\n".join(dis_lines) if dis_lines else "No instructions decoded.")

    def export_findings(self):
        if not self.results:
            QtWidgets.QMessageBox.information(self, "No data", "Nothing to export yet.")
            return
        dest, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Findings", "findings.json", "JSON Files (*.json)")
        if not dest:
            return
        export_findings(list(self.results.values()), Path(dest))
        QtWidgets.QMessageBox.information(self, "Export complete", f"Saved to {dest}")


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
