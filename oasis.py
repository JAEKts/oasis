###############################################################################
# oasis.py
#
# OASIS - Open Architecture Security Interception Suite.
# A Python-based open-source alternative to Burp Suite, with Obsidian-like vault
# for persistent state management, and mitmproxy for HTTP/HTTPS interception.
###############################################################################

import sys
import os
import json
import asyncio
import time
import uuid
import traceback
from typing import Dict, Any, List, Optional, Tuple

# PyQt5 + qasync for GUI + event loop
from PyQt5 import QtCore, QtGui, QtWidgets
import qasync

# Attempt to import mitmproxy
try:
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy import http
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    print("[WARNING] mitmproxy not installed - real proxy interception won't run.")

###############################################################################
# State Manager (Obsidian-like)
###############################################################################
class StateManager:
    """
    Maintains a "vault" folder containing all data (requests, repeater state, config).
    Similar to an Obsidian vault, everything is auto-saved in JSON.
    """

    def __init__(self, vault_path: str):
        self.vault_path = vault_path
        os.makedirs(self.vault_path, exist_ok=True)

        self.state_path = os.path.join(self.vault_path, "state.json")
        self.state_data: Dict[str, Any] = {
            "requests": [],
            "repeater_tabs": {},
            "config": {
                "theme": "dark"
            }
        }
        self.load_state()

    def load_state(self):
        if os.path.isfile(self.state_path):
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    self.state_data = json.load(f)
            except Exception as e:
                print(f"Error loading state from {self.state_path}: {e}")

    def save_state(self):
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(self.state_data, f, indent=2)
        except Exception as e:
            print(f"Error saving state to {self.state_path}: {e}")

    def get_requests(self) -> List[Dict[str, Any]]:
        return self.state_data.get("requests", [])

    def add_request(self, req_data: Dict[str, Any]):
        self.state_data.setdefault("requests", []).append(req_data)
        self.save_state()

    def get_repeater_tabs(self) -> Dict[str, Dict[str, Any]]:
        return self.state_data.get("repeater_tabs", {})

    def save_repeater_tab(self, tab_name: str, tab_data: Dict[str, Any]):
        self.state_data.setdefault("repeater_tabs", {})[tab_name] = tab_data
        self.save_state()

    def get_config(self) -> Dict[str, Any]:
        return self.state_data.get("config", {})

    def set_theme(self, theme: str):
        self.state_data["config"]["theme"] = theme
        self.save_state()

###############################################################################
# Proxy Interceptor (mitmproxy Addon)
###############################################################################
class ProxyInterceptor:
    """
    A mitmproxy addon that intercepts and logs requests into the StateManager.
    """
    def __init__(self, state_manager: StateManager):
        self.state_manager = state_manager

    def response(self, flow: http.HTTPFlow):
        """Intercept every response to log data."""
        request_info = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "body": flow.request.get_text(strict=False) or "",
            "status_code": flow.response.status_code,
            "response": flow.response.get_text(strict=False) or "",
        }
        self.state_manager.add_request(request_info)

###############################################################################
# Asynchronous mitmproxy runner
###############################################################################
async def run_mitmproxy(state_manager: StateManager):
    if not MITMPROXY_AVAILABLE:
        return
    try:
        options = Options(listen_host="127.0.0.1", listen_port=8080)
        dump_master = DumpMaster(options, with_termlog=False, with_dumper=False)
        interceptor = ProxyInterceptor(state_manager)
        dump_master.addons.add(interceptor)
        await dump_master.run()
    except Exception as e:
        print("[mitmproxy error]", e)
        traceback.print_exc()

###############################################################################
# Model / Data Classes for Qt
###############################################################################
class RequestEntry:
    def __init__(self, data: Dict[str, Any]):
        self.data = data

class RequestTableModel(QtCore.QAbstractTableModel):
    """
    A basic table model showing the captured requests from the StateManager.
    """
    def __init__(self, requests: List[Dict[str, Any]]):
        super().__init__()
        self.requests = [RequestEntry(r) for r in requests]
        self.headers = ["ID", "Method", "URL", "Status"]  # minimal

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.requests)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.headers)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid() or role != QtCore.Qt.DisplayRole:
            return None
        row, col = index.row(), index.column()
        req = self.requests[row].data
        if col == 0:
            return req.get("id", "")
        elif col == 1:
            return req.get("method", "")
        elif col == 2:
            return req.get("url", "")
        elif col == 3:
            return str(req.get("status_code", ""))
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if orientation == QtCore.Qt.Horizontal and role == QtCore.Qt.DisplayRole:
            return self.headers[section]
        return None

    def setRequests(self, reqs: List[Dict[str, Any]]):
        self.beginResetModel()
        self.requests = [RequestEntry(r) for r in reqs]
        self.endResetModel()

    def getRequest(self, row: int) -> Optional[Dict[str, Any]]:
        if 0 <= row < len(self.requests):
            return self.requests[row].data
        return None

###############################################################################
# Raw HTTP Editor (Repeater)
###############################################################################
class RawHttpEditor(QtWidgets.QTextEdit):
    """
    A simple raw HTTP editor that can parse out method, URL, headers, body.
    """
    def get_request_parts(self) -> Tuple[str, str, str, str]:
        raw = self.toPlainText()
        lines = raw.splitlines()
        if not lines:
            return ("GET", "http://example.com", "", "")

        # Parse first line: METHOD URL ...
        first_line = lines[0].strip()
        method, url = "GET", "http://example.com"
        if " " in first_line:
            parts = first_line.split(None, 2)
            if len(parts) >= 2:
                method, url = parts[0], parts[1]

        # Headers until blank line
        header_lines = []
        body_lines = []
        blank_index = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                blank_index = i
                break
            header_lines.append(line)

        if blank_index is not None:
            body_lines = lines[blank_index+1:]

        headers_str = "\n".join(header_lines)
        body_str = "\n".join(body_lines)
        return (method, url, headers_str, body_str)

    def set_request_parts(self, method: str, url: str, headers: str, body: str):
        text_lines = []
        text_lines.append(f"{method} {url} HTTP/1.1")
        if headers:
            text_lines.extend(headers.split("\n"))
        text_lines.append("")  # blank line
        if body:
            text_lines.append(body)
        self.setPlainText("\n".join(text_lines))

###############################################################################
# ProxyTab
###############################################################################
class ProxyTab(QtWidgets.QWidget):
    sendToRepeaterSignal = QtCore.pyqtSignal(dict)
    sendToTestCaseSignal = QtCore.pyqtSignal(dict)

    def __init__(self, state_manager: StateManager, parent=None):
        super().__init__(parent)
        self.state_manager = state_manager
        self.setup_ui()
        self.start_refresh_timer()

    def setup_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Filter area
        filter_layout = QtWidgets.QHBoxLayout()
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by method or URL...")
        self.filter_btn = QtWidgets.QPushButton("Filter")
        self.filter_btn.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_edit)
        filter_layout.addWidget(self.filter_btn)
        layout.addLayout(filter_layout)

        # Table
        self.model = RequestTableModel(self.state_manager.get_requests())
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.context_menu)
        layout.addWidget(self.table)

        self.setLayout(layout)

    def start_refresh_timer(self):
        self.refresh_timer = QtCore.QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_requests)
        self.refresh_timer.start(2000)

    def refresh_requests(self):
        all_reqs = self.state_manager.get_requests()
        self.model.setRequests(all_reqs)

    def apply_filter(self):
        text = self.filter_edit.text().lower().strip()
        if not text:
            self.model.setRequests(self.state_manager.get_requests())
            return

        filtered = []
        for req in self.state_manager.get_requests():
            if text in req.get("method", "").lower() or text in req.get("url", "").lower():
                filtered.append(req)
        self.model.setRequests(filtered)

    def context_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        req = self.model.getRequest(row)
        if not req:
            return

        menu = QtWidgets.QMenu(self)
        to_repeater_action = menu.addAction("Send to Repeater")
        to_testcase_action = menu.addAction("Send to Test Cases")
        selected = menu.exec_(self.table.mapToGlobal(pos))
        if selected == to_repeater_action:
            self.sendToRepeaterSignal.emit(req)
        elif selected == to_testcase_action:
            self.sendToTestCaseSignal.emit(req)

###############################################################################
# RepeaterTab
###############################################################################
class RepeaterTab(QtWidgets.QWidget):
    def __init__(self, state_manager: StateManager, parent=None):
        super().__init__(parent)
        self.state_manager = state_manager
        self.current_tab_name: Optional[str] = None

        # History for undo/redo
        self.history: List[Dict[str, Any]] = []
        self.history_index = -1

        self.init_ui()
        self.load_tabs_list()

    def init_ui(self):
        main_layout = QtWidgets.QHBoxLayout(self)

        # Left side: repeater tabs list
        self.tab_list = QtWidgets.QListWidget()
        self.tab_list.itemClicked.connect(self.on_tab_selected)
        main_layout.addWidget(self.tab_list, 1)

        # Right side: raw editor + response
        right_layout = QtWidgets.QVBoxLayout()

        self.raw_label = QtWidgets.QLabel("Raw HTTP Editor:")
        right_layout.addWidget(self.raw_label)

        self.raw_editor = RawHttpEditor()
        right_layout.addWidget(self.raw_editor, 3)

        # Buttons row
        button_layout = QtWidgets.QHBoxLayout()
        self.undo_btn = QtWidgets.QPushButton("Undo")
        self.undo_btn.clicked.connect(self.undo_history)
        self.redo_btn = QtWidgets.QPushButton("Redo")
        self.redo_btn.clicked.connect(self.redo_history)
        self.send_btn = QtWidgets.QPushButton("Send")
        self.send_btn.clicked.connect(self.send_request)

        button_layout.addWidget(self.undo_btn)
        button_layout.addWidget(self.redo_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.send_btn)

        right_layout.addLayout(button_layout)

        # Response
        self.response_view = QtWidgets.QTextEdit()
        self.response_view.setReadOnly(True)
        right_layout.addWidget(QtWidgets.QLabel("Response:"), 0)
        right_layout.addWidget(self.response_view, 2)

        main_layout.addLayout(right_layout, 2)
        self.setLayout(main_layout)

    def load_tabs_list(self):
        self.tab_list.clear()
        all_tabs = self.state_manager.get_repeater_tabs()
        for name in all_tabs.keys():
            self.tab_list.addItem(name)

    def on_tab_selected(self, item: QtWidgets.QListWidgetItem):
        name = item.text()
        self.current_tab_name = name
        self.history.clear()
        self.history_index = -1

        tab_data = self.state_manager.get_repeater_tabs().get(name, {})
        method = tab_data.get("method", "GET")
        url = tab_data.get("url", "http://example.com")
        headers = tab_data.get("headers", "")
        body = tab_data.get("body", "")

        self.raw_editor.set_request_parts(method, url, headers, body)
        self.response_view.clear()

    def create_new_tab(self, name: str):
        # if user-named tab already exists, create unique name
        tabs = self.state_manager.get_repeater_tabs()
        orig = name
        idx = 1
        while name in tabs:
            name = f"{orig}_{idx}"
            idx += 1

        tab_data = {
            "name": name,
            "method": "GET",
            "url": "http://example.com",
            "headers": "",
            "body": ""
        }
        self.state_manager.save_repeater_tab(name, tab_data)
        self.load_tabs_list()

    def load_request_from_proxy(self, req: Dict[str, Any]):
        # create a new tab with request details
        name = f"Request_{req.get('id', uuid.uuid4().hex[:5])}"
        tabs = self.state_manager.get_repeater_tabs()
        idx = 1
        original_name = name
        while name in tabs:
            name = f"{original_name}_{idx}"
            idx += 1
        tab_data = {
            "name": name,
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "headers": "\n".join(
                f"{k}: {v}" for k, v in req.get("headers", {}).items()
            ),
            "body": req.get("body", "")
        }
        self.state_manager.save_repeater_tab(name, tab_data)
        self.load_tabs_list()

    def send_request(self):
        method, url, headers_str, body_str = self.raw_editor.get_request_parts()
        headers_dict = {}
        for line in headers_str.split("\n"):
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip()] = v.strip()

        # Send with requests
        import requests
        try:
            r = requests.request(method, url, headers=headers_dict, data=body_str)
            status_code = r.status_code
            resp_text = r.text
        except Exception as e:
            status_code = 0
            resp_text = f"Error: {e}"

        self.response_view.setPlainText(f"Status: {status_code}\n\n{resp_text}")
        # push to history
        raw_text = self.raw_editor.toPlainText()
        new_state = {
            "raw_text": raw_text,
            "status_code": status_code,
            "response_text": resp_text
        }
        self.push_history(new_state)

        # auto-save changes if we have a current tab
        if self.current_tab_name:
            tab_data = {
                "name": self.current_tab_name,
                "method": method,
                "url": url,
                "headers": headers_str,
                "body": body_str
            }
            self.state_manager.save_repeater_tab(self.current_tab_name, tab_data)

    def push_history(self, state: Dict[str, Any]):
        # if we undone some steps, and we do a new send, cut off forward states
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]
        self.history.append(state)
        self.history_index = len(self.history) - 1

    def undo_history(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.apply_history(self.history[self.history_index])

    def redo_history(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.apply_history(self.history[self.history_index])

    def apply_history(self, state: Dict[str, Any]):
        self.raw_editor.setPlainText(state["raw_text"])
        self.response_view.setPlainText(
            f"Status: {state['status_code']}\n\n{state['response_text']}"
        )

###############################################################################
# TestCaseTab (Placeholder)
###############################################################################
class TestCaseTab(QtWidgets.QWidget):
    def __init__(self, state_manager: StateManager, parent=None):
        super().__init__(parent)
        self.state_manager = state_manager
        layout = QtWidgets.QVBoxLayout(self)
        label = QtWidgets.QLabel("Test Case Management Placeholder")
        layout.addWidget(label)
        self.setLayout(layout)

###############################################################################
# LoggerTab (Placeholder)
###############################################################################
class LoggerTab(QtWidgets.QWidget):
    sendToRepeaterSignal = QtCore.pyqtSignal(dict)
    sendToTestCaseSignal = QtCore.pyqtSignal(dict)

    def __init__(self, state_manager: StateManager, parent=None):
        super().__init__(parent)
        self.state_manager = state_manager
        layout = QtWidgets.QVBoxLayout(self)
        label = QtWidgets.QLabel("Logger Tab Placeholder")
        layout.addWidget(label)
        self.setLayout(layout)

###############################################################################
# OverviewTab (Placeholder)
###############################################################################
class OverviewTab(QtWidgets.QWidget):
    goToProxySignal = QtCore.pyqtSignal()
    goToRepeaterSignal = QtCore.pyqtSignal()
    goToTestCaseSignal = QtCore.pyqtSignal()
    goToLoggerSignal = QtCore.pyqtSignal()

    def __init__(self, state_manager: StateManager, parent=None):
        super().__init__(parent)
        self.state_manager = state_manager
        layout = QtWidgets.QVBoxLayout(self)

        label = QtWidgets.QLabel("Overview / Dashboard Placeholder")
        layout.addWidget(label)

        btn_layout = QtWidgets.QHBoxLayout()
        self.proxy_btn = QtWidgets.QPushButton("Go to Proxy")
        self.repeater_btn = QtWidgets.QPushButton("Go to Repeater")
        self.testcase_btn = QtWidgets.QPushButton("Go to Test Cases")
        self.logger_btn = QtWidgets.QPushButton("Go to Logger")

        self.proxy_btn.clicked.connect(self.goToProxySignal)
        self.repeater_btn.clicked.connect(self.goToRepeaterSignal)
        self.testcase_btn.clicked.connect(self.goToTestCaseSignal)
        self.logger_btn.clicked.connect(self.goToLoggerSignal)

        btn_layout.addWidget(self.proxy_btn)
        btn_layout.addWidget(self.repeater_btn)
        btn_layout.addWidget(self.testcase_btn)
        btn_layout.addWidget(self.logger_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

###############################################################################
# Main Window
###############################################################################
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, state_manager: StateManager):
        super().__init__()
        self.state_manager = state_manager
        self.setWindowTitle("OASIS - Open Architecture Security Interception Suite")
        self.resize(1200, 800)
        self.init_ui()

    def init_ui(self):
        self.tab_widget = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.overview_tab = OverviewTab(self.state_manager)
        self.proxy_tab = ProxyTab(self.state_manager)
        self.repeater_tab = RepeaterTab(self.state_manager)
        self.testcase_tab = TestCaseTab(self.state_manager)
        self.logger_tab = LoggerTab(self.state_manager)

        self.tab_widget.addTab(self.overview_tab, "Overview")
        self.tab_widget.addTab(self.proxy_tab, "Proxy")
        self.tab_widget.addTab(self.repeater_tab, "Repeater")
        self.tab_widget.addTab(self.testcase_tab, "Test Cases")
        self.tab_widget.addTab(self.logger_tab, "Logger")

        # Cross-tab signals
        self.overview_tab.goToProxySignal.connect(
            lambda: self.tab_widget.setCurrentWidget(self.proxy_tab)
        )
        self.overview_tab.goToRepeaterSignal.connect(
            lambda: self.tab_widget.setCurrentWidget(self.repeater_tab)
        )
        self.overview_tab.goToTestCaseSignal.connect(
            lambda: self.tab_widget.setCurrentWidget(self.testcase_tab)
        )
        self.overview_tab.goToLoggerSignal.connect(
            lambda: self.tab_widget.setCurrentWidget(self.logger_tab)
        )

        self.proxy_tab.sendToRepeaterSignal.connect(self.send_to_repeater)
        self.proxy_tab.sendToTestCaseSignal.connect(self.send_to_testcase)

        self.init_menubar()
        self.apply_theme(self.state_manager.get_config().get("theme", "dark"))

    def init_menubar(self):
        menubar = self.menuBar()
        project_menu = menubar.addMenu("Project")

        new_tab_action = QtWidgets.QAction("New Repeater Tab", self)
        new_tab_action.triggered.connect(self.prompt_new_repeater_tab)
        project_menu.addAction(new_tab_action)

        # Theme toggles
        dark_theme_action = QtWidgets.QAction("Dark Theme", self)
        dark_theme_action.triggered.connect(lambda: self.set_theme("dark"))
        project_menu.addAction(dark_theme_action)

        light_theme_action = QtWidgets.QAction("Light Theme", self)
        light_theme_action.triggered.connect(lambda: self.set_theme("light"))
        project_menu.addAction(light_theme_action)

    def prompt_new_repeater_tab(self):
        name, ok = QtWidgets.QInputDialog.getText(
            self, "New Repeater Tab", "Tab Name:"
        )
        if ok and name.strip():
            self.repeater_tab.create_new_tab(name.strip())

    def send_to_repeater(self, req: Dict[str, Any]):
        self.tab_widget.setCurrentWidget(self.repeater_tab)
        self.repeater_tab.load_request_from_proxy(req)

    def send_to_testcase(self, req: Dict[str, Any]):
        self.tab_widget.setCurrentWidget(self.testcase_tab)
        # Expand logic to automatically add a test entry, if desired.

    def set_theme(self, theme_name: str):
        self.state_manager.set_theme(theme_name)
        self.apply_theme(theme_name)

    def apply_theme(self, theme_name: str):
        if theme_name == "dark":
            self.set_dark_theme()
        else:
            self.set_light_theme()

    def set_dark_theme(self):
        app = QtWidgets.QApplication.instance()
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(35, 35, 35))
        palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
        palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
        palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
        palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(142, 45, 197).lighter())
        palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
        app.setStyle("Fusion")
        app.setPalette(palette)
        font = app.font()
        font.setPointSize(11)
        app.setFont(font)

    def set_light_theme(self):
        app = QtWidgets.QApplication.instance()
        app.setStyle("Fusion")
        app.setPalette(app.style().standardPalette())
        font = app.font()
        font.setPointSize(11)
        app.setFont(font)

###############################################################################
# main()
###############################################################################
def main():
    app = QtWidgets.QApplication(sys.argv)
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    # Create vault folder if not present
    vault_path = os.path.join(os.getcwd(), "oasis_vault")
    state_manager = StateManager(vault_path)

    window = MainWindow(state_manager)
    window.show()

    # If mitmproxy is installed, spin up the proxy
    if MITMPROXY_AVAILABLE:
        asyncio.ensure_future(run_mitmproxy(state_manager))
    else:
        print("[INFO] Launching without real mitmproxy proxy.")

    with loop:
        loop.run_forever()

if __name__ == "__main__":
    main()
