"""SpecProbe: PySide6 desktop UI.

Paste any Swagger/OpenAPI URL (or open a local spec file), click Load, and get a
tree of endpoints with a request builder, a response viewer and a contract check
against the spec.

All network I/O runs on QThread workers so the UI never blocks. Everything that
comes from a spec or a server is untrusted, and is shown as plain text or escaped.
"""

from __future__ import annotations

import gc
import html
import json
import logging
import os
import sys
import time
import traceback
from typing import Any, Callable, Optional
from urllib.parse import quote, urlsplit

try:
    from PySide6 import QtCore, QtGui, QtWidgets
except ImportError as e:  # pragma: no cover - depends on the install, not on the code
    raise SystemExit(
        'The desktop UI needs PySide6. Install it with: pip install "PySide6>=6.6" '
        "The CLI works without it."
    ) from e

from . import __version__
from .core import (
    Auth,
    AuditRow,
    CallResult,
    Endpoint,
    RequestParts,
    body_text_for_editor,
    build_url,
    default_param_value,
    deref,
    example_body,
    example_from_schema,
    execute_call,
    extract_field_errors,
    fetch_spec,
    find_endpoint,
    find_login_candidates,
    guess_login_shape,
    is_local_source,
    login,
    normalize_url,
    origins_differ,
    param_enum,
    param_type_label,
    parse_body_text,
    parse_endpoints,
    parse_security_schemes,
    plan_audit,
    run_audit,
    resolve_auth_url,
    response_schema,
    server_urls,
    spec_title,
    spec_version_label,
    split_param_values,
    to_curl,
    validate_response,
    with_query,
)

METHOD_COLORS = {
    "GET": "#3b82f6",
    "POST": "#10b981",
    "PUT": "#f59e0b",
    "PATCH": "#a855f7",
    "DELETE": "#ef4444",
    "OPTIONS": "#6b7280",
    "HEAD": "#6b7280",
    "TRACE": "#6b7280",
}
MUTED = "#6b7280"
OK_COLOR = "#10b981"
BAD_COLOR = "#ef4444"
WARN_COLOR = "#f59e0b"

SETTINGS_ORG = "SpecProbe"
SETTINGS_APP = "SpecProbe"

MAX_RECENT_URLS = 15
MAX_HISTORY = 200
MAX_HISTORY_BODY = 2_000_000
MAX_DISPLAY_CHARS = 2_000_000
MAX_HIGHLIGHT_CHARS = 300_000

_LIVE_WORKERS: set = set()
_HAYSTACK_ROLE = QtCore.Qt.UserRole + 1


def _filter_haystack(ep: Endpoint) -> str:
    """The text the endpoint filter searches, built once per load."""
    return f"{ep.method} {ep.path} {ep.summary} {ep.operation_id} {' '.join(ep.tags)}".lower()


def _settings() -> QtCore.QSettings:
    return QtCore.QSettings(SETTINGS_ORG, SETTINGS_APP)


def _mono_font(size: int = 10) -> QtGui.QFont:
    font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
    font.setPointSize(size)
    return font


def _colored(color: str, text: str) -> str:
    """Rich-text span. `text` is escaped, because it may come from a server."""
    return f"<span style='color:{color}'>{html.escape(str(text))}</span>"


def profile_key(source: str) -> str:
    """Settings are per API: one key per host, or per file for a local spec."""
    source = (source or "").strip()
    if not source:
        return ""
    if is_local_source(source):
        name = os.path.basename(urlsplit(source).path if "://" in source else source)
        return quote("file_" + name, safe="")
    try:
        return quote(urlsplit(normalize_url(source)).netloc.lower(), safe="")
    except (ValueError, RuntimeError):
        return ""


def load_profile(key: str) -> dict:
    if not key:
        return {}
    raw = _settings().value(f"profiles/{key}", "", str)
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def save_profile(key: str, profile: dict) -> None:
    if key:
        _settings().setValue(f"profiles/{key}", json.dumps(profile))


class Worker(QtCore.QThread):
    """Run any callable on a background thread; emit done(result) or failed(msg).

    A module-level set owns every running worker. Destroying a QThread that is
    still running aborts the process, which is otherwise easy to hit by closing a
    dialog or cancelling mid-request.
    """

    done = QtCore.Signal(object)
    failed = QtCore.Signal(str)

    def __init__(self, fn: Callable, *args, **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        _LIVE_WORKERS.add(self)
        self.finished.connect(self._release)

    def _release(self):
        self.wait()
        _LIVE_WORKERS.discard(self)

    def run(self):
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as e:
            self.failed.emit(f"{e}\n{traceback.format_exc()}")
            return
        self.done.emit(result)


class AuditWorker(QtCore.QThread):
    """Run the planned audit one endpoint at a time, reporting each row."""

    row_ready = QtCore.Signal(object)

    def __init__(self, targets: list, base: str, jobs: int = 1, **options):
        super().__init__()
        self._targets = targets
        self._base = base
        self._jobs = jobs
        self._options = options
        self.stop_requested = False
        _LIVE_WORKERS.add(self)
        self.finished.connect(self._release)

    def _release(self):
        self.wait()
        _LIVE_WORKERS.discard(self)

    def run(self):
        if self.stop_requested:
            return
        rows = run_audit(self._targets, self._base, jobs=self._jobs, **self._options)
        try:
            for row in rows:
                self.row_ready.emit(row)
                if self.stop_requested:
                    return
        finally:
            rows.close()  # cancels calls not yet started


class LogBridge(QtCore.QObject):
    message = QtCore.Signal(str)


class QtLogHandler(logging.Handler):
    """Forward log records across threads to the Log tab via a queued signal."""

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.bridge = LogBridge()
        self.setFormatter(logging.Formatter("%(asctime)s  %(message)s", "%H:%M:%S"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.bridge.message.emit(self.format(record))
        except RuntimeError:  # the window is already gone at shutdown
            pass


class JsonHighlighter(QtGui.QSyntaxHighlighter):
    """Minimal JSON colorizer: keys, strings, numbers, keywords.

    One regex tokenizes each line left to right. Separate per-kind passes would
    pair a closing quote with the next opening quote, as in `"a": "b"`.
    """

    TOKEN = QtCore.QRegularExpression(
        r'("(?:\\.|[^"\\])*")(\s*:)?'
        r"|(-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)"
        r"|\b(true|false|null)\b"
    )

    def __init__(self, doc):
        super().__init__(doc)
        self.key_format = self._fmt("#a855f7", bold=True)
        self.string_format = self._fmt(OK_COLOR)
        self.number_format = self._fmt(WARN_COLOR)
        self.keyword_format = self._fmt("#3b82f6", bold=True)

    @staticmethod
    def _fmt(color: str, bold: bool = False) -> QtGui.QTextCharFormat:
        f = QtGui.QTextCharFormat()
        f.setForeground(QtGui.QColor(color))
        if bold:
            f.setFontWeight(QtGui.QFont.DemiBold)
        return f

    def highlightBlock(self, text: str):
        it = self.TOKEN.globalMatch(text)
        while it.hasNext():
            m = it.next()
            if m.capturedStart(1) >= 0:
                fmt = self.key_format if m.capturedStart(2) >= 0 else self.string_format
                self.setFormat(m.capturedStart(1), m.capturedLength(1), fmt)
            elif m.capturedStart(3) >= 0:
                self.setFormat(m.capturedStart(3), m.capturedLength(3), self.number_format)
            else:
                self.setFormat(m.capturedStart(4), m.capturedLength(4), self.keyword_format)


def _plain_label(text: str = "") -> QtWidgets.QLabel:
    """A selectable label that never interprets its text as rich text."""
    label = QtWidgets.QLabel(text)
    label.setTextFormat(QtCore.Qt.PlainText)
    label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)
    return label


class LoginDialog(QtWidgets.QDialog):
    def __init__(
        self,
        parent: QtWidgets.QWidget,
        base_url: str,
        verify_tls: bool,
        *,
        spec: Optional[dict] = None,
        endpoints: Optional[list[Endpoint]] = None,
        remembered: Optional[dict] = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Login")
        self.resize(640, 540)
        self.base_url = base_url
        self.verify_tls = verify_tls
        self.spec = spec or {}
        self.endpoints = endpoints or []
        self.token: Optional[str] = None
        self.cookies: dict = {}
        self.raw_response: Any = None
        self._worker: Optional[Worker] = None
        self._missing_fields: list[str] = []

        form = QtWidgets.QFormLayout()
        self.auth_url = QtWidgets.QComboBox()
        self.auth_url.setEditable(True)
        self.auth_url.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.auth_url.lineEdit().setPlaceholderText("Full URL or path of the login endpoint")
        self._candidates = self._candidate_urls()
        self.auth_url.addItems(list(self._candidates))
        self.auth_url.activated.connect(self._apply_candidate_shape)
        self.field_name = QtWidgets.QComboBox()
        self.field_name.addItems(["username", "email", "userName", "login"])
        self.field_name.setEditable(True)
        self.field_name.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.password_field = QtWidgets.QLineEdit("password")
        self.send_as = QtWidgets.QComboBox()
        self.send_as.addItem("JSON", False)
        self.send_as.addItem("Form-encoded (OAuth2 password grant)", True)
        self.token_path = QtWidgets.QLineEdit()
        self.token_path.setPlaceholderText("Optional, e.g. result.auth.jwt. Blank = search common names")
        self.username = QtWidgets.QLineEdit()
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.Password)
        form.addRow("Auth URL:", self.auth_url)
        form.addRow("Username field:", self.field_name)
        form.addRow("Password field:", self.password_field)
        form.addRow("Send as:", self.send_as)
        form.addRow("Token path:", self.token_path)
        form.addRow("Username / Email:", self.username)
        form.addRow("Password:", self.password)

        # Enter in these fields submits the login. See the note on buttons below.
        self.auth_url.lineEdit().returnPressed.connect(self.do_login)
        self.username.returnPressed.connect(self.do_login)
        self.password.returnPressed.connect(self.do_login)

        extra_header = QtWidgets.QHBoxLayout()
        extra_header.addWidget(QtWidgets.QLabel("Extra fields (optional):"))
        extra_header.addStretch()
        add_field_btn = QtWidgets.QPushButton("+ Add field")
        add_field_btn.clicked.connect(lambda: self._add_extra_row())
        remove_field_btn = QtWidgets.QPushButton("- Remove")
        remove_field_btn.clicked.connect(self._remove_extra_row)
        extra_header.addWidget(add_field_btn)
        extra_header.addWidget(remove_field_btn)

        self.extra_table = QtWidgets.QTableWidget(0, 2)
        self.extra_table.setHorizontalHeaderLabels(["Field", "Value"])
        self.extra_table.horizontalHeader().setStretchLastSection(True)
        self.extra_table.verticalHeader().setVisible(False)
        self.extra_table.setMaximumHeight(110)

        self.add_missing_btn = QtWidgets.QPushButton("")
        self.add_missing_btn.setVisible(False)
        self.add_missing_btn.clicked.connect(self._add_missing_fields)

        self.advanced_toggle = QtWidgets.QCheckBox("Advanced: edit the raw request body (JSON)")
        self.advanced_toggle.toggled.connect(self._toggle_advanced)
        self.body_edit = QtWidgets.QPlainTextEdit()
        self.body_edit.setFont(_mono_font())
        self.body_edit.setVisible(False)
        self.body_edit.setMaximumHeight(140)
        self._body_highlighter = JsonHighlighter(self.body_edit.document())

        self.status = QtWidgets.QLabel("")
        self.status.setWordWrap(True)
        self.status.setTextFormat(QtCore.Qt.RichText)
        self.status.setStyleSheet("QLabel { padding: 4px; }")
        self.status.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse | QtCore.Qt.TextSelectableByKeyboard)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Cancel)
        self.login_btn = QtWidgets.QPushButton("Login")
        btns.addButton(self.login_btn, QtWidgets.QDialogButtonBox.ActionRole)
        self.login_btn.clicked.connect(self.do_login)
        btns.rejected.connect(self.reject)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addLayout(form)
        layout.addLayout(extra_header)
        layout.addWidget(self.extra_table)
        layout.addWidget(self.add_missing_btn)
        layout.addWidget(self.advanced_toggle)
        layout.addWidget(self.body_edit, 1)
        layout.addWidget(self.status)
        layout.addWidget(btns)

        # No button here may be a Qt "default" button. Qt's default-button
        # mechanism fires on any unhandled Enter anywhere in the dialog, such as
        # after committing an Extra fields cell, and that would submit the login.
        # Enter-to-submit is wired above to specific fields instead. Walking every
        # child means a button added later can't reintroduce the problem.
        for btn in self.findChildren(QtWidgets.QPushButton):
            btn.setAutoDefault(False)
            btn.setDefault(False)

        self._restore(remembered or {})
        self.username.setFocus()

    def _candidate_urls(self) -> dict[str, Optional[Endpoint]]:
        """Absolute login URLs suggested by the spec, with their endpoint if known."""
        out: dict[str, Optional[Endpoint]] = {}
        for candidate in find_login_candidates(self.endpoints, self.spec):
            ep = find_endpoint(self.endpoints, "POST", candidate)
            if ep is not None:
                url = build_url(self.base_url, candidate)
            else:
                url = resolve_auth_url(self.base_url, candidate)
            out[url] = ep
        return out

    def _apply_candidate_shape(self, *_):
        ep = self._candidates.get(self.auth_url.currentText().strip())
        if ep is None:
            return
        shape = guess_login_shape(ep, self.spec)
        if shape.username_field:
            self.field_name.setEditText(shape.username_field)
        if shape.password_field:
            self.password_field.setText(shape.password_field)
        self.send_as.setCurrentIndex(1 if shape.form else 0)
        existing = set(self._extra_fields())
        for name in shape.extra_required:
            if name not in existing:
                self._add_extra_row(name)

    def _restore(self, remembered: dict):
        if remembered.get("auth_url"):
            self.auth_url.setEditText(str(remembered["auth_url"]))
            if remembered.get("field"):
                self.field_name.setEditText(str(remembered["field"]))
            self.password_field.setText(str(remembered.get("password_field") or "password"))
            self.send_as.setCurrentIndex(1 if remembered.get("form") else 0)
            self.token_path.setText(str(remembered.get("token_path") or ""))
            extra = remembered.get("extra")
            if isinstance(extra, dict):
                for k, v in extra.items():
                    self._add_extra_row(str(k), str(v))
            self.username.setText(str(remembered.get("username") or ""))
        elif self._candidates:
            self.auth_url.setCurrentIndex(0)
            self._apply_candidate_shape()
        else:
            parts = urlsplit(self.base_url)
            self.auth_url.setEditText(f"{parts.scheme}://{parts.netloc}/" if parts.netloc else "")

    def remembered(self) -> dict:
        """Non-secret values worth reusing for this API. Never includes the password."""
        return {
            "auth_url": self.auth_url.currentText().strip(),
            "field": self.field_name.currentText().strip(),
            "password_field": self.password_field.text().strip(),
            "form": bool(self.send_as.currentData()),
            "token_path": self.token_path.text().strip(),
            "extra": self._extra_fields(),
            "username": self.username.text().strip(),
        }

    def _toggle_advanced(self, checked: bool):
        self.body_edit.setVisible(checked)
        if checked:
            self.body_edit.setPlainText(json.dumps(self._build_body(), indent=2, ensure_ascii=False))

    def _build_body(self) -> dict:
        body = {
            self.field_name.currentText().strip() or "username": self.username.text().strip(),
            self.password_field.text().strip() or "password": self.password.text(),
        }
        body.update(self._extra_fields())
        return body

    def _extra_fields(self) -> dict:
        out: dict = {}
        for r in range(self.extra_table.rowCount()):
            k_item = self.extra_table.item(r, 0)
            k = k_item.text().strip() if k_item else ""
            if not k:
                continue
            v_item = self.extra_table.item(r, 1)
            out[k] = v_item.text().strip() if v_item else ""
        return out

    def _add_extra_row(self, key: str = "", value: str = ""):
        row = self.extra_table.rowCount()
        self.extra_table.insertRow(row)
        self.extra_table.setItem(row, 0, QtWidgets.QTableWidgetItem(key))
        self.extra_table.setItem(row, 1, QtWidgets.QTableWidgetItem(value))
        self.extra_table.setCurrentCell(row, 1 if key else 0)

    def _remove_extra_row(self):
        rows = sorted({idx.row() for idx in self.extra_table.selectedIndexes()}, reverse=True)
        for r in rows:
            self.extra_table.removeRow(r)

    def _add_missing_fields(self):
        existing = set(self._extra_fields())
        for name in self._missing_fields:
            if name not in existing:
                self._add_extra_row(name)
        self.add_missing_btn.setVisible(False)

    def do_login(self):
        if self._worker and self._worker.isRunning():
            return
        body_override = None
        if self.advanced_toggle.isChecked() and self.body_edit.toPlainText().strip():
            try:
                body_override = json.loads(self.body_edit.toPlainText())
            except json.JSONDecodeError as e:
                self.status.setText(_colored(BAD_COLOR, f"Body is not valid JSON: {e}"))
                return
            if not isinstance(body_override, dict):
                self.status.setText(_colored(BAD_COLOR, "The body must be a JSON object."))
                return
        username = self.username.text().strip()
        password = self.password.text()
        if body_override is None and (not username or not password):
            self.status.setText(_colored(BAD_COLOR, "Username and password are required."))
            return

        target = self.auth_url.currentText().strip()
        if target.lower().startswith(("http://", "https://")):
            has_path = urlsplit(target).path.strip("/") != ""
        else:
            has_path = bool(target.strip("/"))
        if not has_path:
            self.status.setText(_colored(BAD_COLOR, "Auth URL needs the login path, e.g. /api/token/."))
            return

        self.status.setText(_colored(MUTED, "Sending login request..."))
        self.login_btn.setEnabled(False)
        self._worker = Worker(
            login,
            self.base_url,
            username,
            password,
            auth_path=target,
            username_field=self.field_name.currentText().strip() or "username",
            password_field=self.password_field.text().strip() or "password",
            extra_fields=self._extra_fields(),
            form=bool(self.send_as.currentData()),
            token_path=self.token_path.text().strip() or None,
            verify=self.verify_tls,
            body_override=body_override,
        )
        self._worker.done.connect(self._on_login_done)
        self._worker.failed.connect(self._on_login_failed)
        self._worker.start()

    def _on_login_failed(self, msg: str):
        self.login_btn.setEnabled(True)
        first_line = msg.splitlines()[0] if msg else "unknown error"
        self.status.setText(_colored(BAD_COLOR, f"Request failed: {first_line}"))

    def _on_login_done(self, result):
        self.login_btn.setEnabled(True)
        self.raw_response = result.body
        self.add_missing_btn.setVisible(False)
        if result.ok:
            self.token = result.token
            self.cookies = result.cookies
            self.accept()
            return
        preview = json.dumps(self.raw_response, ensure_ascii=False, default=str)[:500]
        headline = (
            f"Login failed (HTTP {result.status})."
            if result.status >= 400
            else "The server accepted this, but no token or session cookie was found. "
                 "If the token is in an unusual place, set Token path."
        )
        hint = self._field_error_hint(extract_field_errors(self.raw_response))
        self.status.setText(
            f"{_colored(BAD_COLOR, headline)}{hint}"
            f"<br><code style='font-size:10px'>{html.escape(preview)}</code>"
        )

    def _field_error_hint(self, errors: dict) -> str:
        """Offer a fix based on the fields the backend complained about."""
        if not errors:
            return ""
        names = list(errors)
        current = (self.field_name.currentText().strip() or "username").lower()
        password_field = (self.password_field.text().strip() or "password").lower()
        username_like = [
            f for f in names
            if f.lower() != current and any(w in f.lower() for w in ("user", "email", "login"))
        ]
        hint = ""
        if username_like:
            suggestion = html.escape(username_like[0])
            hint = (f"<br><span style='color:{WARN_COLOR}'>Hint: the backend complained about field "
                    f"<b>{suggestion}</b>. Try setting 'Username field' to <b>{suggestion}</b>.</span>")
        skip = {current, password_field} | {f.lower() for f in username_like}
        others = [f for f in names if f.lower() not in skip]
        if others:
            self._missing_fields = others
            self.add_missing_btn.setText(f"Add missing field(s) as extra fields: {', '.join(others)}")
            self.add_missing_btn.setVisible(True)
        if not hint and not others:
            hint = "<br>" + _colored(WARN_COLOR, f"Backend errors: {', '.join(names)}")
        return hint


class AuditDialog(QtWidgets.QDialog):
    """GUI front end for the same audit the CLI runs."""

    COLUMNS = ["Result", "Status", "ms", "Tag", "Endpoint", "Contract"]

    def __init__(self, window: "MainWindow"):
        super().__init__(window)
        self.window_ref = window
        self.setWindowTitle("Audit GET endpoints")
        self.resize(980, 640)
        self._worker: Optional[AuditWorker] = None
        self._rows: list[AuditRow] = []
        self._skipped: list[dict] = []
        self._total = 0

        intro = QtWidgets.QLabel(
            "Calls every GET endpoint whose required parameters are known. Only GET is "
            "used, so this doesn't intentionally change data. Endpoints that still need "
            "a value are skipped rather than guessed."
        )
        intro.setWordWrap(True)

        form = QtWidgets.QHBoxLayout()
        form.addWidget(QtWidgets.QLabel("Parameter values:"))
        self.params_edit = QtWidgets.QLineEdit()
        self.params_edit.setPlaceholderText("Used for any endpoint, e.g. version=1, tenant=acme")
        form.addWidget(self.params_edit, 1)
        form.addWidget(QtWidgets.QLabel("Tag:"))
        self.tag_combo = QtWidgets.QComboBox()
        self.tag_combo.addItem("All")
        self.tag_combo.addItems(sorted({t for ep in window.endpoints for t in ep.tags}))
        form.addWidget(self.tag_combo)
        self.validate_box = QtWidgets.QCheckBox("Check contract")
        self.validate_box.setChecked(True)
        self.validate_box.setToolTip("Compare each response with the spec")
        form.addWidget(self.validate_box)
        form.addWidget(QtWidgets.QLabel("Parallel:"))
        self.jobs_spin = QtWidgets.QSpinBox()
        self.jobs_spin.setRange(1, 16)
        self.jobs_spin.setValue(1)
        self.jobs_spin.setToolTip("Requests in flight at once. Raise it only for servers that can take the load.")
        form.addWidget(self.jobs_spin)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setValue(0)
        self.summary = _plain_label("")

        self.table = QtWidgets.QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        hh = self.table.horizontalHeader()
        for col in range(4):
            hh.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        hh.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)

        buttons = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start")
        self.start_btn.clicked.connect(self.start)
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        self.export_btn = QtWidgets.QPushButton("Export JSON...")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export)
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addWidget(self.export_btn)
        buttons.addStretch()
        buttons.addWidget(close_btn)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addLayout(form)
        layout.addWidget(self.progress)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.summary)
        layout.addLayout(buttons)
        for btn in self.findChildren(QtWidgets.QPushButton):
            btn.setAutoDefault(False)
            btn.setDefault(False)

    def _parse_params(self) -> dict:
        out: dict = {}
        for chunk in self.params_edit.text().split(","):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                out[k.strip()] = v.strip()
        return out

    def start(self):
        w = self.window_ref
        base = w.base_combo.currentText().strip()
        if not base:
            self.summary.setText("Set a server URL first.")
            return
        tag = self.tag_combo.currentText()
        targets, self._skipped = plan_audit(
            w.endpoints, w.spec,
            params=self._parse_params(),
            tag=None if tag == "All" else tag,
        )
        self.table.setRowCount(0)
        self._rows = []
        self._total = len(targets)
        self.progress.setRange(0, max(self._total, 1))
        self.progress.setValue(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self._worker = AuditWorker(
            targets, base,
            jobs=self.jobs_spin.value(),
            spec=w.spec,
            validate=self.validate_box.isChecked(),
            headers=w.extra_headers(),
            auth=w.current_auth(),
            cookies=dict(w.session_cookies),
            verify=w.verify_tls.isChecked(),
            timeout=w.timeout_spin.value(),
        )
        self._worker.row_ready.connect(self._on_row)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def stop(self):
        if self._worker:
            self._worker.stop_requested = True
            self.stop_btn.setEnabled(False)
            self.summary.setText("Stopping after the current request...")

    def _add_row(self, cells: list[str], color: str):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, text in enumerate(cells):
            item = QtWidgets.QTableWidgetItem(text)
            if col == 0:
                item.setForeground(QtGui.QBrush(QtGui.QColor(color)))
            if col == 5 and text:
                item.setToolTip(html.escape(text))
            self.table.setItem(row, col, item)

    def _on_row(self, row: AuditRow):
        self._rows.append(row)
        colors = {"ok": OK_COLOR, "auth": WARN_COLOR, "client": WARN_COLOR}
        contract = row.error or "; ".join(row.issues)
        self._add_row(
            [row.bucket, str(row.status or "-"), f"{row.ms:.0f}", row.tag, f"{row.method} {row.path}", contract],
            colors.get(row.bucket, BAD_COLOR),
        )
        self.table.scrollToBottom()
        self.progress.setValue(len(self._rows))

    def _on_finished(self):
        for item in self._skipped:
            self._add_row(
                ["skip", "-", "-", "", f"{item['method']} {item['path']}", f"needs: {', '.join(item['missing'])}"],
                MUTED,
            )
        counts: dict[str, int] = {}
        for row in self._rows:
            counts[row.bucket] = counts.get(row.bucket, 0) + 1
        issues = sum(1 for r in self._rows if r.issues)
        parts = [f"{counts[k]} {k}" for k in ("ok", "auth", "client", "server", "error") if counts.get(k)]
        parts.append(f"{len(self._skipped)} skipped")
        if self.validate_box.isChecked():
            parts.append(f"{issues} with contract issues")
        self.summary.setText(", ".join(parts))
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(bool(self._rows))

    def export(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export audit", "audit.json", "JSON (*.json)")
        if path:
            self.write_report(path)

    def write_report(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"results": [r.as_dict() for r in self._rows], "skipped": self._skipped},
                      f, indent=2, ensure_ascii=False)

    def closeEvent(self, ev: QtGui.QCloseEvent):
        self.stop()
        super().closeEvent(ev)

    def reject(self):
        self.stop()
        super().reject()


def _load_and_parse(url: str, **kwargs) -> tuple[dict, str, list[Endpoint]]:
    """Fetch and parse off the UI thread, so a malformed spec fails cleanly."""
    spec, found = fetch_spec(url, **kwargs)
    return spec, found, parse_endpoints(spec)


def _send_and_check(ep: Endpoint, spec: dict, request: dict) -> tuple[CallResult, list[str]]:
    """Send and validate off the UI thread, so large responses can't stall it."""
    result = execute_call(request.pop("method"), request.pop("url"), **request)
    return result, validate_response(ep, result, spec)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SpecProbe")
        self.resize(1500, 920)

        self.spec: Optional[dict] = None
        self.spec_url: Optional[str] = None
        self.endpoints: list[Endpoint] = []
        self.current_endpoint: Optional[Endpoint] = None
        self.session_cookies: dict = {}
        self._busy = False
        self._profile_key = ""
        self._profile: dict = {}
        self._drafts: dict[tuple, dict] = {}
        self._sticky_path_values: dict[str, str] = {}
        self._history: list[dict] = []
        self._last_result: Optional[CallResult] = None
        self._load_worker: Optional[Worker] = None
        self._call_worker: Optional[Worker] = None

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root = QtWidgets.QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        root.addLayout(self._build_toolbar())

        self.base_warning = QtWidgets.QLabel("")
        self.base_warning.setTextFormat(QtCore.Qt.PlainText)
        self.base_warning.setStyleSheet(f"color: {WARN_COLOR}")
        self.base_warning.setVisible(False)
        root.addWidget(self.base_warning)

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.progress.setFixedHeight(3)
        self.progress.setTextVisible(False)
        root.addWidget(self.progress)

        main_split = QtWidgets.QSplitter()
        root.addWidget(main_split, 1)
        main_split.addWidget(self._build_left_panel())

        right = QtWidgets.QWidget()
        rl = QtWidgets.QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)

        header = QtWidgets.QHBoxLayout()
        self.method_label = QtWidgets.QLabel("-")
        method_font = self.method_label.font()
        method_font.setBold(True)
        method_font.setPointSize(13)
        self.method_label.setFont(method_font)
        self.method_label.setMinimumWidth(80)
        self.path_label = _plain_label("Select an endpoint")
        path_font = self.path_label.font()
        path_font.setPointSize(12)
        self.path_label.setFont(path_font)
        header.addWidget(self.method_label)
        header.addWidget(self.path_label, 1)
        rl.addLayout(header)
        self.summary_label = _plain_label("")
        self.summary_label.setWordWrap(True)
        self.summary_label.setStyleSheet(f"color: {MUTED}")
        rl.addWidget(self.summary_label)

        rv = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        rl.addWidget(rv, 1)
        rv.addWidget(self._build_request_panel())
        rv.addWidget(self._build_response_panel())
        rv.setSizes([420, 440])
        main_split.addWidget(right)
        main_split.setSizes([380, 1120])

        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+F"), self, activated=self._focus_filter)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+L"), self, activated=self.url_edit.setFocus)
        QtGui.QShortcut(QtGui.QKeySequence("Ctrl+R"), self, activated=self.load_spec)

        self.statusBar().showMessage(
            "Paste an API docs or spec URL and click Load. "
            "(Ctrl+L address, Ctrl+R reload, Ctrl+F filter, Ctrl+Enter send)"
        )

        self._log_handler = QtLogHandler()
        self._log_handler.bridge.message.connect(self.log_view.appendPlainText)
        logger = logging.getLogger("specprobe")
        logger.addHandler(self._log_handler)
        logger.setLevel(logging.DEBUG)

        self._load_settings()

    # ---- UI construction ----
    def _build_toolbar(self) -> QtWidgets.QGridLayout:
        top = QtWidgets.QGridLayout()
        top.setHorizontalSpacing(8)
        top.setVerticalSpacing(6)

        top.addWidget(QtWidgets.QLabel("API URL:"), 0, 0)
        self.url_edit = QtWidgets.QComboBox()
        self.url_edit.setEditable(True)
        self.url_edit.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.url_edit.lineEdit().setPlaceholderText(
            "Docs page, spec URL, host, or local file, e.g. https://api.example.com/docs"
        )
        self.url_edit.lineEdit().returnPressed.connect(self.load_spec)
        top.addWidget(self.url_edit, 0, 1)
        url_btns = QtWidgets.QHBoxLayout()
        url_btns.setContentsMargins(0, 0, 0, 0)
        self.open_file_btn = QtWidgets.QPushButton("Open file...")
        self.open_file_btn.clicked.connect(self.open_spec_file)
        self.load_btn = QtWidgets.QPushButton("Load")
        self.load_btn.clicked.connect(self.load_spec)
        self.audit_btn = QtWidgets.QPushButton("Audit...")
        self.audit_btn.setToolTip("Call all GET endpoints that need no invented data and summarize")
        self.audit_btn.setEnabled(False)
        self.audit_btn.clicked.connect(self.open_audit)
        url_btns.addWidget(self.open_file_btn)
        url_btns.addWidget(self.load_btn)
        url_btns.addWidget(self.audit_btn)
        top.addLayout(url_btns, 0, 2)

        top.addWidget(QtWidgets.QLabel("Server:"), 1, 0)
        self.base_combo = QtWidgets.QComboBox()
        self.base_combo.setEditable(True)
        self.base_combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.base_combo.lineEdit().setPlaceholderText("Base URL requests are sent to; filled from the spec")
        self.base_combo.currentTextChanged.connect(self._on_base_changed)
        top.addWidget(self.base_combo, 1, 1)
        opts = QtWidgets.QHBoxLayout()
        opts.setContentsMargins(0, 0, 0, 0)
        self.verify_tls = QtWidgets.QCheckBox("Verify TLS")
        self.verify_tls.setToolTip("Turn off only for self-signed development certificates")
        self.timeout_spin = QtWidgets.QSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" s")
        self.timeout_spin.setToolTip("Request timeout")
        opts.addWidget(self.verify_tls)
        opts.addWidget(QtWidgets.QLabel("Timeout:"))
        opts.addWidget(self.timeout_spin)
        opts.addStretch()
        top.addLayout(opts, 1, 2)

        top.addWidget(QtWidgets.QLabel("Auth:"), 2, 0)
        auth_row = QtWidgets.QHBoxLayout()
        auth_row.setContentsMargins(0, 0, 0, 0)
        self.auth_kind = QtWidgets.QComboBox()
        self.auth_kind.addItem("None", "none")
        self.auth_kind.addItem("Bearer / token", "bearer")
        self.auth_kind.addItem("Basic", "basic")
        self.auth_kind.addItem("API key", "apikey")
        self.auth_kind.currentIndexChanged.connect(self._on_auth_kind_changed)
        auth_row.addWidget(self.auth_kind)
        self.auth_stack = QtWidgets.QStackedWidget()
        self.auth_stack.addWidget(QtWidgets.QLabel("Requests are sent without credentials."))

        bearer = QtWidgets.QWidget()
        bl = QtWidgets.QHBoxLayout(bearer)
        bl.setContentsMargins(0, 0, 0, 0)
        self.token_prefix = QtWidgets.QLineEdit("Bearer")
        self.token_prefix.setMaximumWidth(80)
        self.token_prefix.setToolTip('Authorization scheme word. DRF TokenAuth uses "Token". Blank sends the raw token.')
        self.token_edit = QtWidgets.QLineEdit()
        self.token_edit.setPlaceholderText("Paste a token, or click Login...")
        self.token_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        bl.addWidget(self.token_prefix)
        bl.addWidget(self.token_edit, 1)
        self.auth_stack.addWidget(bearer)

        basic = QtWidgets.QWidget()
        bl = QtWidgets.QHBoxLayout(basic)
        bl.setContentsMargins(0, 0, 0, 0)
        self.basic_user = QtWidgets.QLineEdit()
        self.basic_user.setPlaceholderText("Username")
        self.basic_pass = QtWidgets.QLineEdit()
        self.basic_pass.setPlaceholderText("Password")
        self.basic_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        bl.addWidget(self.basic_user, 1)
        bl.addWidget(self.basic_pass, 1)
        self.auth_stack.addWidget(basic)

        apikey = QtWidgets.QWidget()
        bl = QtWidgets.QHBoxLayout(apikey)
        bl.setContentsMargins(0, 0, 0, 0)
        self.apikey_name = QtWidgets.QLineEdit("X-API-Key")
        self.apikey_name.setToolTip("Header, query or cookie name")
        self.apikey_name.setMaximumWidth(180)
        self.apikey_location = QtWidgets.QComboBox()
        self.apikey_location.addItems(["header", "query", "cookie"])
        self.apikey_value = QtWidgets.QLineEdit()
        self.apikey_value.setPlaceholderText("Key value")
        self.apikey_value.setEchoMode(QtWidgets.QLineEdit.Password)
        bl.addWidget(self.apikey_name)
        bl.addWidget(self.apikey_location)
        bl.addWidget(self.apikey_value, 1)
        self.auth_stack.addWidget(apikey)
        auth_row.addWidget(self.auth_stack, 1)
        top.addLayout(auth_row, 2, 1)

        auth_btns = QtWidgets.QHBoxLayout()
        auth_btns.setContentsMargins(0, 0, 0, 0)
        self.show_token = QtWidgets.QCheckBox("Show")
        self.show_token.toggled.connect(self._toggle_secret_echo)
        self.remember_secrets = QtWidgets.QCheckBox("Remember")
        self.remember_secrets.setToolTip(
            "Save this API's credentials in your user settings between launches. "
            "They are stored unencrypted, so leave this off on shared machines."
        )
        self.login_btn = QtWidgets.QPushButton("Login...")
        self.login_btn.clicked.connect(self.open_login)
        self.clear_token_btn = QtWidgets.QPushButton("Clear")
        self.clear_token_btn.setToolTip("Forget the credentials and any session cookies for this API")
        self.clear_token_btn.clicked.connect(self.clear_credentials)
        auth_btns.addWidget(self.show_token)
        auth_btns.addWidget(self.remember_secrets)
        auth_btns.addWidget(self.login_btn)
        auth_btns.addWidget(self.clear_token_btn)
        top.addLayout(auth_btns, 2, 2)
        top.setColumnStretch(1, 1)

        for edit in (self.token_edit, self.basic_user, self.basic_pass, self.apikey_value,
                     self.apikey_name, self.token_prefix):
            edit.textChanged.connect(self._update_base_warning)
        return top

    def _build_left_panel(self) -> QtWidgets.QWidget:
        self.left_tabs = QtWidgets.QTabWidget()

        endpoints = QtWidgets.QWidget()
        ll = QtWidgets.QVBoxLayout(endpoints)
        ll.setContentsMargins(4, 4, 4, 4)
        self.search_edit = QtWidgets.QLineEdit()
        self.search_edit.setPlaceholderText("Filter endpoints... (Ctrl+F)")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self.filter_tree)
        ll.addWidget(self.search_edit)
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setUniformRowHeights(True)
        self.tree.currentItemChanged.connect(self.on_endpoint_selected)
        ll.addWidget(self.tree, 1)
        self.left_tabs.addTab(endpoints, "Endpoints")

        history = QtWidgets.QWidget()
        hl = QtWidgets.QVBoxLayout(history)
        hl.setContentsMargins(4, 4, 4, 4)
        self.history_list = QtWidgets.QListWidget()
        self.history_list.setToolTip("Requests sent this session. Click one to bring it back.")
        self.history_list.currentRowChanged.connect(self._on_history_selected)
        hl.addWidget(self.history_list, 1)
        clear_history = QtWidgets.QPushButton("Clear history")
        clear_history.clicked.connect(self.clear_history)
        hl.addWidget(clear_history)
        self.left_tabs.addTab(history, "History")
        return self.left_tabs

    def _build_request_panel(self) -> QtWidgets.QWidget:
        req = QtWidgets.QWidget()
        rw = QtWidgets.QVBoxLayout(req)
        rw.setContentsMargins(0, 6, 0, 0)

        self.req_tabs = QtWidgets.QTabWidget()

        self.params_table = QtWidgets.QTableWidget(0, 6)
        self.params_table.setHorizontalHeaderLabels(["Name", "In", "Type", "Required", "Value", "Description"])
        hh = self.params_table.horizontalHeader()
        for col in range(4):
            hh.setSectionResizeMode(col, QtWidgets.QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)
        hh.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)
        self.params_table.verticalHeader().setVisible(False)
        self.params_table.itemChanged.connect(self._update_url_preview)
        self.req_tabs.addTab(self.params_table, "Parameters")

        body_tab = QtWidgets.QWidget()
        bt = QtWidgets.QVBoxLayout(body_tab)
        bt.setContentsMargins(4, 4, 4, 4)
        body_row = QtWidgets.QHBoxLayout()
        body_row.addWidget(QtWidgets.QLabel("Content type:"))
        self.content_type = QtWidgets.QComboBox()
        self.content_type.setEditable(True)
        self.content_type.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
        self.content_type.setMinimumWidth(260)
        self.content_type.addItem("application/json")
        self.content_type.currentTextChanged.connect(self._update_body_hint)
        body_row.addWidget(self.content_type)
        body_row.addStretch()
        self.example_btn = QtWidgets.QPushButton("Insert example")
        self.example_btn.clicked.connect(self.insert_example_body)
        self.format_btn = QtWidgets.QPushButton("Format")
        self.format_btn.clicked.connect(self.format_body)
        body_row.addWidget(self.format_btn)
        body_row.addWidget(self.example_btn)
        bt.addLayout(body_row)
        self.body_edit = QtWidgets.QPlainTextEdit()
        self.body_edit.setFont(_mono_font())
        self._body_highlighter = JsonHighlighter(self.body_edit.document())
        bt.addWidget(self.body_edit, 1)
        self.req_tabs.addTab(body_tab, "Body")

        headers_tab = QtWidgets.QWidget()
        ht = QtWidgets.QVBoxLayout(headers_tab)
        ht.setContentsMargins(4, 4, 4, 4)
        header_row = QtWidgets.QHBoxLayout()
        header_row.addWidget(QtWidgets.QLabel("Sent with every request to this API:"))
        header_row.addStretch()
        add_header = QtWidgets.QPushButton("+ Add")
        add_header.clicked.connect(lambda: self._add_header_row())
        remove_header = QtWidgets.QPushButton("- Remove")
        remove_header.clicked.connect(self._remove_header_row)
        header_row.addWidget(add_header)
        header_row.addWidget(remove_header)
        ht.addLayout(header_row)
        self.headers_table = QtWidgets.QTableWidget(0, 2)
        self.headers_table.setHorizontalHeaderLabels(["Header", "Value"])
        self.headers_table.horizontalHeader().setStretchLastSection(True)
        self.headers_table.verticalHeader().setVisible(False)
        ht.addWidget(self.headers_table, 1)
        self.req_tabs.addTab(headers_tab, "Extra headers")

        self.docs_view = QtWidgets.QTextBrowser()
        self.docs_view.setOpenLinks(False)
        self.docs_view.setOpenExternalLinks(False)
        self.req_tabs.addTab(self.docs_view, "Docs")

        rw.addWidget(self.req_tabs, 1)

        send_row = QtWidgets.QHBoxLayout()
        self.send_btn = QtWidgets.QPushButton("Send")
        self.send_btn.setShortcut("Ctrl+Return")
        self.send_btn.setToolTip("Send request (Ctrl+Enter)")
        self.send_btn.setMinimumHeight(32)
        self.send_btn.setMinimumWidth(100)
        self.send_btn.clicked.connect(self.send_request)
        self.send_btn.setEnabled(False)
        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(32)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setToolTip("Stop waiting for the response. The server may still process the request.")
        self.cancel_btn.clicked.connect(self.cancel_request)
        self.curl_btn = QtWidgets.QPushButton("Copy as cURL")
        self.curl_btn.setMinimumHeight(32)
        self.curl_btn.setEnabled(False)
        self.curl_btn.setToolTip("Copy the equivalent curl command, including credentials")
        self.curl_btn.clicked.connect(self.copy_curl)
        send_row.addWidget(self.send_btn)
        send_row.addWidget(self.cancel_btn)
        send_row.addWidget(self.curl_btn)
        self.preview_url_label = _plain_label("")
        self.preview_url_label.setStyleSheet(f"color:{MUTED}")
        self.preview_url_label.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Preferred)
        send_row.addWidget(self.preview_url_label, 1)
        rw.addLayout(send_row)
        return req

    def _build_response_panel(self) -> QtWidgets.QWidget:
        resp = QtWidgets.QWidget()
        rwl = QtWidgets.QVBoxLayout(resp)
        rwl.setContentsMargins(0, 6, 0, 0)
        status_row = QtWidgets.QHBoxLayout()
        self.status_label = QtWidgets.QLabel("Response: -")
        self.status_label.setTextFormat(QtCore.Qt.RichText)
        self.status_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.status_label.setSizePolicy(QtWidgets.QSizePolicy.Ignored, QtWidgets.QSizePolicy.Preferred)
        status_row.addWidget(self.status_label, 1)
        self.copy_resp_btn = QtWidgets.QPushButton("Copy")
        self.copy_resp_btn.setToolTip("Copy the current response tab to the clipboard")
        self.copy_resp_btn.clicked.connect(self.copy_response)
        self.save_resp_btn = QtWidgets.QPushButton("Save...")
        self.save_resp_btn.setToolTip("Save the exact response body to a file (works for binary)")
        self.save_resp_btn.setEnabled(False)
        self.save_resp_btn.clicked.connect(self.save_response)
        status_row.addWidget(self.copy_resp_btn)
        status_row.addWidget(self.save_resp_btn)
        rwl.addLayout(status_row)

        self.resp_tabs = QtWidgets.QTabWidget()
        self.pretty_view = self._make_readonly_text()
        self._pretty_highlighter = JsonHighlighter(self.pretty_view.document())
        self.raw_view = self._make_readonly_text()
        self.headers_view = self._make_readonly_text()
        self.request_view = self._make_readonly_text()
        self.contract_view = self._make_readonly_text()
        self.log_view = self._make_readonly_text()
        self.log_view.setMaximumBlockCount(5000)
        self.resp_tabs.addTab(self.pretty_view, "Pretty")
        self.resp_tabs.addTab(self.raw_view, "Raw")
        self.resp_tabs.addTab(self.headers_view, "Headers")
        self.resp_tabs.addTab(self.request_view, "Request sent")
        self.resp_tabs.addTab(self.contract_view, "Contract")
        self.resp_tabs.addTab(self.log_view, "Log")
        rwl.addWidget(self.resp_tabs, 1)
        return resp

    @staticmethod
    def _make_readonly_text() -> QtWidgets.QPlainTextEdit:
        w = QtWidgets.QPlainTextEdit()
        w.setReadOnly(True)
        w.setFont(_mono_font())
        return w

    def _focus_filter(self):
        self.left_tabs.setCurrentIndex(0)
        self.search_edit.setFocus()

    def _toggle_secret_echo(self, checked: bool):
        mode = QtWidgets.QLineEdit.Normal if checked else QtWidgets.QLineEdit.Password
        for edit in (self.token_edit, self.basic_pass, self.apikey_value):
            edit.setEchoMode(mode)

    def _set_busy(self, busy: bool, message: str = ""):
        self._busy = busy
        self.progress.setVisible(busy)
        self.load_btn.setEnabled(not busy)
        have_ep = self.current_endpoint is not None
        self.send_btn.setEnabled(not busy and have_ep)
        self.curl_btn.setEnabled(have_ep)
        self.cancel_btn.setEnabled(busy and self._call_worker is not None)
        if message:
            self.statusBar().showMessage(message)

    # ---- auth ----
    def _on_auth_kind_changed(self, index: int):
        self.auth_stack.setCurrentIndex(index)
        self._update_base_warning()

    def _set_auth_kind(self, kind: str):
        index = self.auth_kind.findData(kind)
        if index >= 0:
            self.auth_kind.setCurrentIndex(index)

    def current_auth(self) -> Optional[Auth]:
        kind = self.auth_kind.currentData()
        if kind == "bearer" and self.token_edit.text().strip():
            return Auth(kind="bearer", token=self.token_edit.text().strip(), prefix=self.token_prefix.text())
        if kind == "basic" and (self.basic_user.text() or self.basic_pass.text()):
            return Auth(kind="basic", username=self.basic_user.text(), password=self.basic_pass.text())
        if kind == "apikey" and self.apikey_value.text() and self.apikey_name.text().strip():
            return Auth(kind="apikey", name=self.apikey_name.text().strip(),
                        location=self.apikey_location.currentText(), token=self.apikey_value.text())
        return None

    def clear_credentials(self):
        for edit in (self.token_edit, self.basic_user, self.basic_pass, self.apikey_value):
            edit.clear()
        self.session_cookies = {}
        self.statusBar().showMessage("Credentials cleared.", 3000)
        self._update_base_warning()

    def _apply_spec_auth_hint(self):
        """Start from the scheme the spec declares, unless this API has saved choices."""
        schemes = parse_security_schemes(self.spec or {})
        names = ", ".join(f"{s.key} ({s.kind})" for s in schemes)
        self.auth_kind.setToolTip(f"Declared by this spec: {names}" if names else "This spec declares no auth")
        if self._profile.get("auth"):
            return
        for scheme in schemes:
            auth = scheme.to_auth()
            if auth is None:
                continue
            self._set_auth_kind(auth.kind)
            if auth.kind == "bearer":
                self.token_prefix.setText(auth.prefix)
            elif auth.kind == "apikey":
                self.apikey_name.setText(auth.name)
                self.apikey_location.setCurrentText(auth.location)
            return

    def _update_base_warning(self, *_):
        base = self.base_combo.currentText().strip()
        foreign = bool(self.spec_url) and origins_differ(base, self.spec_url or "")
        if foreign and (self.current_auth() or self.session_cookies):
            host = urlsplit(base).netloc
            self.base_warning.setText(f"Requests, including your credentials, go to {host}, "
                                      "which isn't the host this spec was loaded from.")
            self.base_warning.setVisible(True)
        else:
            self.base_warning.setVisible(False)

    def _on_base_changed(self, *_):
        self._update_base_warning()
        self._update_url_preview()

    # ---- extra headers ----
    def _add_header_row(self, name: str = "", value: str = ""):
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        self.headers_table.setItem(row, 0, QtWidgets.QTableWidgetItem(name))
        self.headers_table.setItem(row, 1, QtWidgets.QTableWidgetItem(value))

    def _remove_header_row(self):
        for r in sorted({i.row() for i in self.headers_table.selectedIndexes()}, reverse=True):
            self.headers_table.removeRow(r)

    def extra_headers(self) -> dict:
        out: dict = {}
        for r in range(self.headers_table.rowCount()):
            key_item = self.headers_table.item(r, 0)
            key = key_item.text().strip() if key_item else ""
            if key:
                value_item = self.headers_table.item(r, 1)
                out[key] = value_item.text() if value_item else ""
        return out

    # ---- settings and per-API profiles ----
    def _load_settings(self):
        s = _settings()
        # Older versions stored the token unconditionally in plaintext. Remove it,
        # along with the old login values that were shared between all APIs.
        s.remove("main/token")
        s.remove("login")
        try:
            recent = json.loads(s.value("main/recent", "[]", str))
        except ValueError:
            recent = []
        self.url_edit.addItems([str(u) for u in recent if u])
        self.url_edit.setEditText(s.value("main/url", "", str))
        self.verify_tls.setChecked(s.value("main/verify_tls", True, bool))
        self.timeout_spin.setValue(int(s.value("main/timeout", 30, int)))
        self.remember_secrets.setChecked(s.value("main/remember_secrets", False, bool))
        geo = s.value("main/geometry")
        if geo:
            self.restoreGeometry(geo)

    def _remember_url(self, url: str):
        existing = [self.url_edit.itemText(i) for i in range(self.url_edit.count())]
        recent = [url] + [u for u in existing if u != url]
        recent = recent[:MAX_RECENT_URLS]
        self.url_edit.blockSignals(True)
        self.url_edit.clear()
        self.url_edit.addItems(recent)
        self.url_edit.setEditText(url)
        self.url_edit.blockSignals(False)
        _settings().setValue("main/recent", json.dumps(recent))

    def _collect_profile(self) -> dict:
        profile = dict(self._profile)
        declared = server_urls(self.spec, self.spec_url) if (self.spec and self.spec_url) else []
        base = self.base_combo.currentText().strip()
        if base and declared and base != declared[0]:
            profile["base"] = base
        else:
            profile.pop("base", None)
        profile["auth"] = {
            "kind": self.auth_kind.currentData(),
            "prefix": self.token_prefix.text(),
            "name": self.apikey_name.text(),
            "location": self.apikey_location.currentText(),
        }
        profile["headers"] = self.extra_headers()
        if self.remember_secrets.isChecked():
            profile["secrets"] = {
                "token": self.token_edit.text(),
                "basic_user": self.basic_user.text(),
                "basic_pass": self.basic_pass.text(),
                "apikey": self.apikey_value.text(),
            }
        else:
            profile.pop("secrets", None)
        return profile

    def _store_profile(self):
        if self._profile_key:
            self._profile = self._collect_profile()
            save_profile(self._profile_key, self._profile)

    def _apply_profile(self, key: str):
        """Switch to the saved settings of another API.

        Credentials never carry over: a token typed for one API must not be sent
        to a different one just because a new URL was pasted.
        """
        previous = self._profile_key
        self._profile_key = key
        self._profile = load_profile(key)
        if previous and previous != key:
            for edit in (self.token_edit, self.basic_user, self.basic_pass, self.apikey_value):
                edit.clear()
            self.session_cookies = {}
            self._set_auth_kind("none")
        auth = self._profile.get("auth")
        if isinstance(auth, dict):
            self._set_auth_kind(str(auth.get("kind") or "none"))
            self.token_prefix.setText(str(auth.get("prefix", "Bearer")))
            self.apikey_name.setText(str(auth.get("name") or "X-API-Key"))
            self.apikey_location.setCurrentText(str(auth.get("location") or "header"))
        self.headers_table.setRowCount(0)
        headers = self._profile.get("headers")
        if isinstance(headers, dict):
            for name, value in headers.items():
                self._add_header_row(str(name), str(value))
        secrets = self._profile.get("secrets")
        if isinstance(secrets, dict):
            self.token_edit.setText(str(secrets.get("token") or ""))
            self.basic_user.setText(str(secrets.get("basic_user") or ""))
            self.basic_pass.setText(str(secrets.get("basic_pass") or ""))
            self.apikey_value.setText(str(secrets.get("apikey") or ""))

    def closeEvent(self, ev: QtGui.QCloseEvent):
        self._store_profile()
        s = _settings()
        s.setValue("main/url", self.url_edit.currentText())
        s.setValue("main/verify_tls", self.verify_tls.isChecked())
        s.setValue("main/timeout", self.timeout_spin.value())
        s.setValue("main/remember_secrets", self.remember_secrets.isChecked())
        s.setValue("main/geometry", self.saveGeometry())
        logging.getLogger("specprobe").removeHandler(self._log_handler)
        super().closeEvent(ev)

    # ---- spec loading ----
    def open_spec_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Open OpenAPI/Swagger file", "", "OpenAPI specs (*.json *.yaml *.yml);;All files (*)"
        )
        if path:
            self.url_edit.setEditText(path)
            self.load_spec()

    def load_spec(self):
        url = self.url_edit.currentText().strip()
        if not url or (self._load_worker and self._load_worker.isRunning()):
            return
        key = profile_key(url)
        same_api = not self._profile_key or key == self._profile_key
        self._set_busy(True, f"Fetching spec from {url}...")
        self._load_worker = Worker(
            _load_and_parse,
            url,
            verify=self.verify_tls.isChecked(),
            # Credentials for one API must not be offered to another one's URL.
            headers=self.extra_headers() if same_api else None,
            auth=self.current_auth() if same_api else None,
            timeout=min(self.timeout_spin.value(), 30),
        )
        self._load_worker.done.connect(self._on_spec_loaded)
        self._load_worker.failed.connect(self._on_spec_failed)
        self._load_worker.start()

    def _on_spec_failed(self, msg: str):
        self._set_busy(False, "Load failed.")
        first_line = msg.splitlines()[0] if msg else "unknown error"
        box = QtWidgets.QMessageBox(QtWidgets.QMessageBox.Critical, "Load failed", first_line,
                                    QtWidgets.QMessageBox.Ok, self)
        box.setTextFormat(QtCore.Qt.PlainText)
        box.exec()

    def _on_spec_loaded(self, result):
        spec, found, endpoints = result
        source = self.url_edit.currentText().strip()
        self._store_profile()
        if found != self.spec_url:
            self._drafts = {}
            self._sticky_path_values = {}
        self.current_endpoint = None
        self.spec = spec
        self.spec_url = found
        self.endpoints = endpoints
        self._apply_profile(profile_key(source))
        self._apply_spec_auth_hint()

        self.base_combo.blockSignals(True)
        self.base_combo.clear()
        self.base_combo.addItems(server_urls(spec, found))
        saved_base = self._profile.get("base")
        if saved_base:
            self.base_combo.setEditText(str(saved_base))
        self.base_combo.blockSignals(False)

        self.populate_tree()
        self._clear_request_panel()
        self.search_edit.clear()
        self.audit_btn.setEnabled(bool(endpoints))
        self._remember_url(source)
        self._update_base_warning()
        title = spec_title(spec)
        self.setWindowTitle(f"{title} - SpecProbe")
        hint = "" if self.base_combo.currentText().strip() else " Set the Server URL to send requests."
        self._set_busy(False, f"Loaded {title} ({spec_version_label(spec)}): "
                              f"{len(endpoints)} endpoints from {found}.{hint}")

    def _clear_request_panel(self):
        self.method_label.setText("-")
        self.method_label.setStyleSheet("")
        self.path_label.setText("Select an endpoint")
        self.summary_label.setText("")
        self.params_table.setRowCount(0)
        self.body_edit.setPlainText("")
        self.docs_view.clear()
        self.preview_url_label.setText("")
        self.send_btn.setEnabled(False)
        self.curl_btn.setEnabled(False)

    # ---- tree ----
    def populate_tree(self):
        self.tree.setUpdatesEnabled(False)
        self.tree.blockSignals(True)
        self.tree.clear()
        groups: dict[str, list[Endpoint]] = {}
        for ep in self.endpoints:
            groups.setdefault(ep.tags[0] if ep.tags else "(default)", []).append(ep)
        mono = _mono_font(9)
        for tag in sorted(groups):
            parent = QtWidgets.QTreeWidgetItem([f"{tag}  ({len(groups[tag])})"])
            f = parent.font(0)
            f.setBold(True)
            parent.setFont(0, f)
            self.tree.addTopLevelItem(parent)
            for ep in sorted(groups[tag], key=lambda e: (e.path, e.method)):
                child = QtWidgets.QTreeWidgetItem([f"{ep.method:<7}{ep.path}"])
                child.setData(0, QtCore.Qt.UserRole, ep)
                child.setData(0, _HAYSTACK_ROLE, _filter_haystack(ep))
                child.setForeground(0, QtGui.QBrush(QtGui.QColor(METHOD_COLORS.get(ep.method, MUTED))))
                font = QtGui.QFont(mono)
                font.setStrikeOut(ep.deprecated)
                child.setFont(0, font)
                # Tooltips auto-detect rich text, so wrap and escape spec text explicitly.
                tip = f"{ep.method} {ep.path}"
                if ep.summary:
                    tip += f"\n{ep.summary}"
                if ep.deprecated:
                    tip += "\n(deprecated)"
                child.setToolTip(0, "<p style='white-space:pre-wrap'>" + html.escape(tip) + "</p>")
                parent.addChild(child)
            parent.setExpanded(True)
        self.tree.blockSignals(False)
        self.tree.setUpdatesEnabled(True)

    def filter_tree(self, text: str):
        text = text.lower().strip()
        # Repainting after every item made each keystroke take ~100 ms on large specs.
        self.tree.setUpdatesEnabled(False)
        try:
            for i in range(self.tree.topLevelItemCount()):
                parent = self.tree.topLevelItem(i)
                any_visible = False
                for j in range(parent.childCount()):
                    child = parent.child(j)
                    visible = not text or text in child.data(0, _HAYSTACK_ROLE)
                    if child.isHidden() == visible:
                        child.setHidden(not visible)
                    any_visible = any_visible or visible
                hide_parent = not any_visible and bool(text)
                if parent.isHidden() != hide_parent:
                    parent.setHidden(hide_parent)
        finally:
            self.tree.setUpdatesEnabled(True)

    # ---- request panel ----
    def _param_cell_text(self, row: int) -> str:
        widget = self.params_table.cellWidget(row, 4)
        if isinstance(widget, QtWidgets.QComboBox):
            return widget.currentText()
        item = self.params_table.item(row, 4)
        return item.text() if item else ""

    def _param_values(self) -> dict:
        out: dict = {}
        for r in range(self.params_table.rowCount()):
            key = self.params_table.item(r, 0).data(QtCore.Qt.UserRole)
            out[tuple(key)] = self._param_cell_text(r)
        return out

    @staticmethod
    def _sticky_key(path: str, name: str) -> Optional[str]:
        """Identify a path parameter by the path prefix that ends with it.

        So /tenants/{id} and /tenants/{id}/users share a value, while
        /orders/{id} doesn't inherit one from /users/{id}. Reusing an id across
        unrelated resources could turn a harmless GET's value into a wrong DELETE.
        """
        token = "{" + name + "}"
        at = path.find(token)
        return path[:at + len(token)] if at >= 0 else None

    def _save_draft(self):
        ep = self.current_endpoint
        if ep is None or self.params_table.rowCount() != len(ep.parameters):
            return
        values = self._param_values()
        self._drafts[ep.key] = {
            "values": values,
            "body": self.body_edit.toPlainText(),
            "content_type": self.content_type.currentText(),
        }
        for (name, loc), value in values.items():
            if loc == "path":
                sticky = self._sticky_key(ep.path, name)
                if sticky:
                    if value:
                        self._sticky_path_values[sticky] = value
                    else:
                        self._sticky_path_values.pop(sticky, None)

    def _initial_param_value(self, ep: Endpoint, p: dict, draft: Optional[dict]) -> str:
        name, loc = p.get("name", ""), p.get("in", "")
        if draft is not None and (name, loc) in draft["values"]:
            return draft["values"][(name, loc)]
        if loc == "path":
            sticky = self._sticky_key(ep.path, name)
            if sticky and sticky in self._sticky_path_values:
                return self._sticky_path_values[sticky]
        return default_param_value(p, self.spec) or ""

    def on_endpoint_selected(self, current: QtWidgets.QTreeWidgetItem, _previous=None):
        if not current:
            return
        ep = current.data(0, QtCore.Qt.UserRole)
        if not isinstance(ep, Endpoint):
            return
        self._save_draft()
        self.current_endpoint = ep
        draft = self._drafts.get(ep.key)

        self.method_label.setText(ep.method)
        self.method_label.setStyleSheet(f"color: {METHOD_COLORS.get(ep.method, MUTED)}")
        self.path_label.setText(ep.path + ("  (deprecated)" if ep.deprecated else ""))
        self.summary_label.setText(ep.summary or ep.description or "")

        self.params_table.blockSignals(True)
        self.params_table.setRowCount(0)
        for p in ep.parameters:
            self._add_param_row(ep, p, draft)
        self.params_table.blockSignals(False)
        self.req_tabs.setTabText(0, f"Parameters ({len(ep.parameters)})")

        rb = ep.request_body
        self.content_type.blockSignals(True)
        self.content_type.clear()
        self.content_type.addItems(rb.get("content_types", []) if rb else ["application/json"])
        if rb:
            self.content_type.setCurrentText(rb.get("content_type", "application/json"))
        if draft and draft.get("content_type"):
            self.content_type.setEditText(draft["content_type"])
        self.content_type.blockSignals(False)
        self.body_edit.setPlainText(draft["body"] if draft else "")
        self.example_btn.setEnabled(bool(rb))
        self.req_tabs.setTabText(1, "Body *" if rb and rb.get("required") else "Body")
        self._update_body_hint()

        if ep.parameters:
            self.req_tabs.setCurrentIndex(0)
        elif rb:
            self.req_tabs.setCurrentIndex(1)

        self.docs_view.setHtml(self._docs_html(ep))
        self.send_btn.setEnabled(not self._busy)
        self.curl_btn.setEnabled(True)
        self._update_url_preview()

    def _add_param_row(self, ep: Endpoint, p: dict, draft: Optional[dict]):
        row = self.params_table.rowCount()
        self.params_table.insertRow(row)
        name, loc = p.get("name", ""), p.get("in", "")

        def read_only(text: str) -> QtWidgets.QTableWidgetItem:
            item = QtWidgets.QTableWidgetItem(text)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            return item

        name_item = read_only(name)
        name_item.setData(QtCore.Qt.UserRole, [name, loc])
        required = bool(p.get("required")) or loc == "path"
        if required:
            font = name_item.font()
            font.setBold(True)
            name_item.setFont(font)
        self.params_table.setItem(row, 0, name_item)
        self.params_table.setItem(row, 1, read_only(loc))
        self.params_table.setItem(row, 2, read_only(param_type_label(p, self.spec)))
        self.params_table.setItem(row, 3, read_only("yes" if required else ""))
        description = str(p.get("description") or "")
        desc_item = read_only(description)
        if description:
            desc_item.setToolTip("<p>" + html.escape(description) + "</p>")
        self.params_table.setItem(row, 5, desc_item)

        value = self._initial_param_value(ep, p, draft)
        choices = param_enum(p, self.spec)
        if choices:
            combo = QtWidgets.QComboBox()
            combo.setEditable(True)
            combo.setInsertPolicy(QtWidgets.QComboBox.NoInsert)
            combo.addItems([""] + choices)
            combo.setCurrentText(value)
            combo.currentTextChanged.connect(self._update_url_preview)
            self.params_table.setCellWidget(row, 4, combo)
        else:
            self.params_table.setItem(row, 4, QtWidgets.QTableWidgetItem(value))

    def _update_body_hint(self, *_):
        ct = self.content_type.currentText().lower()
        if "multipart" in ct:
            hint = 'Write a JSON object. Use "@/path/to/file" as a value to upload that file.'
        elif "x-www-form-urlencoded" in ct:
            hint = "Write a JSON object. It's sent as form fields."
        elif "json" in ct:
            hint = "JSON body. 'Insert example' fills it from the schema when the spec has one."
        else:
            hint = "Sent as raw text."
        if self.current_endpoint is not None and not self.current_endpoint.request_body:
            hint = "The spec declares no body for this endpoint. Anything entered here is still sent. " + hint
        self.body_edit.setPlaceholderText(hint)

    def _docs_html(self, ep: Endpoint) -> str:
        """Operation reference. Every spec value is escaped: the spec is untrusted."""
        esc = html.escape
        out = [f"<h3>{esc(ep.method)} {esc(ep.path)}</h3>"]
        if ep.deprecated:
            out.append(f"<p style='color:{WARN_COLOR}'><b>Deprecated</b></p>")
        if ep.summary:
            out.append(f"<p><b>{esc(ep.summary)}</b></p>")
        if ep.description and ep.description != ep.summary:
            out.append(f"<p style='white-space:pre-wrap'>{esc(ep.description)}</p>")
        meta = []
        if ep.operation_id:
            meta.append(f"operationId: <code>{esc(ep.operation_id)}</code>")
        security = ep.security if ep.security is not None else (self.spec or {}).get("security")
        if isinstance(security, list):
            names = sorted({str(k) for item in security if isinstance(item, dict) for k in item})
            meta.append("auth: " + (esc(", ".join(names)) if names else "none"))
        if meta:
            out.append("<p>" + " &nbsp;|&nbsp; ".join(meta) + "</p>")
        if ep.request_body:
            types = ", ".join(ep.request_body.get("content_types", []))
            required = " (required)" if ep.request_body.get("required") else ""
            out.append(f"<h4>Request body{required}: {esc(types)}</h4>")
            sample = example_body(ep, self.spec or {})
            if sample is not None:
                out.append("<pre>" + esc(json.dumps(sample, indent=2, ensure_ascii=False, default=str)) + "</pre>")
        if ep.responses:
            out.append("<h4>Responses</h4>")
            for code in sorted(ep.responses, key=str):
                resolved = deref(ep.responses[code], self.spec or {})
                resolved = resolved if isinstance(resolved, dict) else {}
                out.append(f"<p><b>{esc(str(code))}</b> {esc(str(resolved.get('description') or ''))}</p>")
                schema = response_schema(resolved)
                if schema:
                    sample = example_from_schema(schema, self.spec or {}, mode="response")
                    if sample is not None:
                        out.append("<pre>" + esc(json.dumps(sample, indent=2, ensure_ascii=False, default=str)) + "</pre>")
        return "".join(out)

    def _mark_missing(self, missing: list[str]):
        """Tint empty required value cells."""
        tint = QtGui.QBrush(QtGui.QColor(239, 68, 68, 45))
        clear = QtGui.QBrush()
        self.params_table.blockSignals(True)
        for r in range(self.params_table.rowCount()):
            item = self.params_table.item(r, 4)
            name = self.params_table.item(r, 0).text()
            if item is not None:
                item.setBackground(tint if name in missing else clear)
        self.params_table.blockSignals(False)

    def _update_url_preview(self, *_):
        ep = self.current_endpoint
        if not (ep and self.spec):
            self.preview_url_label.setText("")
            return
        parts = split_param_values(ep, self._param_values(), self.spec)
        self._mark_missing(parts.missing)
        base = self.base_combo.currentText().strip()
        url = build_url(base, ep.path, parts.path_params)
        text = with_query(url, parts.query)
        self.preview_url_label.setText(text)
        self.preview_url_label.setToolTip("<p>" + html.escape(text) + "</p>")

    def insert_example_body(self):
        ep = self.current_endpoint
        if not (ep and ep.request_body and self.spec):
            return
        content_type = self.content_type.currentText().strip()
        value = example_body(ep, self.spec, content_type)
        self.body_edit.setPlainText(body_text_for_editor(value, content_type))

    def format_body(self):
        text = self.body_edit.toPlainText().strip()
        if not text:
            return
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            QtWidgets.QMessageBox.warning(self, "Cannot format", f"Body is not valid JSON:\n{e}")
            return
        self.body_edit.setPlainText(json.dumps(obj, indent=2, ensure_ascii=False))

    # ---- send ----
    def _gather_request(self) -> tuple[dict, RequestParts]:
        """Everything needed to send the current request. Raises ValueError on bad input."""
        ep = self.current_endpoint
        parts = split_param_values(ep, self._param_values(), self.spec)
        base = self.base_combo.currentText().strip()
        if not base:
            raise ValueError("Set the Server URL first. This spec doesn't say which host serves the API.")
        content_type = self.content_type.currentText().strip() or "application/json"
        body = parse_body_text(self.body_edit.toPlainText(), content_type)
        request = {
            "method": ep.method,
            "url": build_url(base, ep.path, parts.path_params),
            "headers": {**self.extra_headers(), **parts.headers},
            "query": parts.query,
            "body": body,
            "content_type": content_type,
            "auth": self.current_auth(),
            "cookies": {**self.session_cookies, **parts.cookies},
            "verify": self.verify_tls.isChecked(),
        }
        return request, parts

    def send_request(self):
        if not (self.current_endpoint and self.spec):
            return
        if self._call_worker and self._call_worker.isRunning():
            return
        ep = self.current_endpoint
        try:
            request, parts = self._gather_request()
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Can't send", str(e))
            return

        unfilled = [name for name in parts.missing if "{" + name + "}" in ep.path]
        if unfilled:
            self.req_tabs.setCurrentIndex(0)
            self.status_label.setText(_colored(BAD_COLOR, "Fill in path parameter(s): " + ", ".join(unfilled)))
            return
        note = ""
        other_missing = [name for name in parts.missing if name not in unfilled]
        if other_missing:
            note = "Sent without required: " + ", ".join(other_missing)

        self._save_draft()
        self.status_label.setText(_colored(MUTED, "Sending..."))
        self._call_worker = Worker(
            _send_and_check, ep, self.spec,
            {**request, "timeout": self.timeout_spin.value()},
        )
        self._call_worker.done.connect(self._on_call_done)
        self._call_worker.failed.connect(self._on_call_failed)
        self._call_started = time.monotonic()
        self._call_note = note
        self._call_snapshot = (ep.key, self._drafts.get(ep.key))
        self._set_busy(True, f"{ep.method} {request['url']}")
        self._call_worker.start()

    def cancel_request(self):
        """Stop waiting. The thread can't be interrupted, so its result is ignored."""
        self._call_worker = None
        self._set_busy(False, "Cancelled. The server may still process the request.")
        self.status_label.setText(_colored(WARN_COLOR, "Cancelled"))

    def copy_curl(self):
        if not self.current_endpoint:
            return
        try:
            request, _parts = self._gather_request()
        except ValueError as e:
            QtWidgets.QMessageBox.warning(self, "Can't build the command", str(e))
            return
        command = to_curl(request.pop("method"), request.pop("url"), **request)
        QtGui.QGuiApplication.clipboard().setText(command)
        self.statusBar().showMessage("curl command copied. It includes your credentials.", 4000)

    def _on_call_failed(self, msg: str):
        if self.sender() is not self._call_worker:
            return
        self._call_worker = None
        self._set_busy(False, "Request failed.")
        self._show_failure(msg)

    def _show_failure(self, msg: str):
        first_line = msg.splitlines()[0] if msg else "unknown error"
        self.status_label.setText(
            f"<span style='color:{BAD_COLOR};font-weight:bold'>ERROR</span> &nbsp; {html.escape(first_line)}"
        )
        for view in (self.pretty_view, self.headers_view, self.request_view, self.contract_view):
            view.setPlainText("")
        self.raw_view.setPlainText(msg)
        self.resp_tabs.setCurrentWidget(self.raw_view)
        self.save_resp_btn.setEnabled(False)
        self._last_result = None
        self.resp_tabs.setTabText(4, "Contract")

    def _on_call_done(self, payload: tuple[CallResult, list[str]]):
        if self.sender() is not self._call_worker:
            return
        self._call_worker = None
        result, issues = payload
        self._set_busy(False, "Ready.")
        self._add_history(result, issues)
        self._show_result(result, issues, self._call_note)

    def _show_result(self, result: CallResult, issues: list[str], note: str = ""):
        if result.error:
            self._show_failure(result.error)
            return
        self._last_result = result
        self.save_resp_btn.setEnabled(True)
        color = OK_COLOR if result.status < 400 else BAD_COLOR
        contract = ""
        if issues:
            contract = f" &nbsp;&nbsp; <span style='color:{WARN_COLOR}'>contract: {len(issues)} issue(s)</span>"
        elif self.current_endpoint is not None and self.current_endpoint.responses:
            contract = f" &nbsp;&nbsp; <span style='color:{OK_COLOR}'>contract: OK</span>"
        extra = f" &nbsp;&nbsp; {_colored(WARN_COLOR, note)}" if note else ""
        self.status_label.setText(
            f"<span style='color:{color};font-weight:bold'>{result.status} {html.escape(result.reason)}</span>"
            f" &nbsp;&nbsp; {result.elapsed_ms:.0f} ms"
            f" &nbsp;&nbsp; {_human_size(result.size)}{contract}{extra}"
            f" &nbsp;&nbsp; <code>{html.escape(result.method)} {html.escape(result.url)}</code>"
        )

        if result.is_binary:
            pretty = raw = (f"<binary response: {_human_size(result.size)}, "
                            f"{result.content_type or 'unknown type'}. Use Save... to keep it.>")
        else:
            raw = result.text
            pretty = json.dumps(result.json, indent=2, ensure_ascii=False) if result.json is not None else result.text
        self._set_large_text(self.pretty_view, pretty, self._pretty_highlighter)
        self._set_large_text(self.raw_view, raw)
        self.headers_view.setPlainText("\n".join(f"{k}: {v}" for k, v in result.headers.items()))
        self.request_view.setPlainText(self._request_summary(result))
        self.contract_view.setPlainText(
            "\n".join(issues) if issues else "The response matches what the spec documents."
            if (self.current_endpoint and self.current_endpoint.responses)
            else "This operation documents no responses to compare with."
        )
        self.resp_tabs.setTabText(4, f"Contract ({len(issues)})" if issues else "Contract")
        self.resp_tabs.setCurrentIndex(0)

    @staticmethod
    def _request_summary(result: CallResult) -> str:
        lines = [f"{result.method} {result.url}"]
        for k, v in result.request_headers.items():
            if k.lower() in ("authorization", "cookie", "proxy-authorization"):
                v = "*** (hidden)"
            lines.append(f"{k}: {v}")
        if result.request_body:
            lines += ["", result.request_body]
        return "\n".join(lines)

    @staticmethod
    def _set_large_text(view: QtWidgets.QPlainTextEdit, text: str,
                        highlighter: Optional[JsonHighlighter] = None):
        """Keep the UI responsive on huge responses: limit highlighting and display."""
        if highlighter is not None:
            highlighter.setDocument(view.document() if len(text) <= MAX_HIGHLIGHT_CHARS else None)
        if len(text) > MAX_DISPLAY_CHARS:
            text = text[:MAX_DISPLAY_CHARS] + "\n\n... display truncated. Use Save... for the full response."
        view.setPlainText(text)

    def copy_response(self):
        widget = self.resp_tabs.currentWidget()
        if isinstance(widget, QtWidgets.QPlainTextEdit):
            QtGui.QGuiApplication.clipboard().setText(widget.toPlainText())
            self.statusBar().showMessage("Copied to clipboard.", 3000)

    def save_response(self):
        if not self._last_result:
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save response", "response")
        if path:
            self.write_response(path)

    def write_response(self, path: str) -> None:
        result = self._last_result
        try:
            with open(path, "wb") as f:
                f.write(result.content or result.text.encode("utf-8"))
        except OSError as e:
            QtWidgets.QMessageBox.warning(self, "Couldn't save", str(e))
            return
        self.statusBar().showMessage(f"Saved {_human_size(result.size)} to {path}", 4000)

    # ---- history ----
    def _add_history(self, result: CallResult, issues: list[str]):
        key, draft = self._call_snapshot
        keep = result if result.size <= MAX_HISTORY_BODY else None
        self._history.insert(0, {
            "key": key,
            "draft": dict(draft) if draft else None,
            "result": keep,
            "issues": issues,
            "note": "" if keep else "Response too large to keep in history.",
        })
        del self._history[MAX_HISTORY:]
        status = "ERR" if result.error else str(result.status)
        label = f"{time.strftime('%H:%M:%S')}  {status:<4}{key[0]:<7}{key[1]}"
        self.history_list.blockSignals(True)
        item = QtWidgets.QListWidgetItem(label)
        item.setFont(_mono_font(9))
        if result.error or result.status >= 400:
            item.setForeground(QtGui.QBrush(QtGui.QColor(BAD_COLOR)))
        self.history_list.insertItem(0, item)
        while self.history_list.count() > MAX_HISTORY:
            self.history_list.takeItem(self.history_list.count() - 1)
        self.history_list.setCurrentRow(-1)
        self.history_list.blockSignals(False)

    def _on_history_selected(self, row: int):
        if not 0 <= row < len(self._history):
            return
        entry = self._history[row]
        # Keep unsaved edits to the current endpoint, then detach from it so that
        # re-selecting can't overwrite the restored request with the current one.
        self._save_draft()
        self.current_endpoint = None
        if entry["draft"]:
            self._drafts[entry["key"]] = dict(entry["draft"])
        self._select_endpoint(*entry["key"])
        if entry["result"] is not None:
            self._show_result(entry["result"], entry["issues"])
        else:
            self.status_label.setText(_colored(MUTED, entry["note"]))

    def _select_endpoint(self, method: str, path: str):
        for i in range(self.tree.topLevelItemCount()):
            parent = self.tree.topLevelItem(i)
            for j in range(parent.childCount()):
                child = parent.child(j)
                ep = child.data(0, QtCore.Qt.UserRole)
                if ep.key == (method, path):
                    if self.tree.currentItem() is child:
                        self.on_endpoint_selected(child)
                    else:
                        self.tree.setCurrentItem(child)
                    return

    def clear_history(self):
        self._history = []
        self.history_list.clear()

    # ---- dialogs ----
    def open_login(self):
        source = self.url_edit.currentText().strip()
        if self.spec and self.base_combo.currentText().strip():
            base = self.base_combo.currentText().strip()
        elif source and not is_local_source(source):
            base = normalize_url(source)
        else:
            base = ""
        dlg = LoginDialog(
            self, base, self.verify_tls.isChecked(),
            spec=self.spec, endpoints=self.endpoints,
            remembered=self._profile.get("login") if isinstance(self._profile.get("login"), dict) else None,
        )
        if dlg.exec() == QtWidgets.QDialog.Accepted:
            self._profile["login"] = dlg.remembered()
            if not self._profile_key:
                self._profile_key = profile_key(source)
            self._store_profile()
            if dlg.cookies:
                self.session_cookies = dlg.cookies
            if dlg.token:
                self._set_auth_kind("bearer")
                self.token_edit.setText(dlg.token)
                self.statusBar().showMessage(f"Logged in. Captured a token ({len(dlg.token)} chars).")
            else:
                self.statusBar().showMessage(f"Logged in with a cookie session ({', '.join(dlg.cookies)}).")
            self._update_base_warning()
        dlg.deleteLater()

    def open_audit(self):
        dlg = AuditDialog(self)
        dlg.exec()
        dlg.deleteLater()


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def neutral_alternate_base(*_) -> None:
    """Keep AlternateBase a neutral grey in dark mode.

    Windows' dark palette makes it navy, and Fusion paints unticked checkboxes
    with it. Called at startup and whenever the system colour scheme changes.
    """
    app = QtWidgets.QApplication.instance()
    QtWidgets.QApplication.setPalette(QtGui.QPalette())  # back to the system palette
    if app.styleHints().colorScheme() != QtCore.Qt.ColorScheme.Dark:
        return
    role = QtGui.QPalette.ColorRole
    base, text = app.palette().color(role.Base), app.palette().color(role.Text)
    mixed = QtGui.QColor(*(round(b + (t - b) * 0.06) for b, t in zip(base.getRgb()[:3], text.getRgb()[:3])))
    override = QtGui.QPalette()
    override.setColor(role.AlternateBase, mixed)
    QtWidgets.QApplication.setPalette(override)


def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("SpecProbe")
    app.setApplicationVersion(__version__)
    app.setOrganizationName(SETTINGS_ORG)
    app.setStyle("Fusion")  # same look on every OS; follows the system light or dark theme
    neutral_alternate_base()
    app.styleHints().colorSchemeChanged.connect(neutral_alternate_base)
    win = MainWindow()
    win.show()
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        win.url_edit.setEditText(sys.argv[1])
        win.load_spec()
    code = app.exec()
    if _LIVE_WORKERS:
        # A request is still running and QThreads can't be stopped safely. Ending
        # the process directly avoids Qt's abort on destroying a running thread.
        _hard_exit(code)
    # Free the window while QApplication still exists. Left to interpreter
    # shutdown, PySide6 6.12 aborts the process about half the time.
    win.deleteLater()
    app.sendPostedEvents(None, QtCore.QEvent.DeferredDelete)
    del win
    gc.collect()
    sys.exit(code)


def _hard_exit(code: int) -> None:
    """End the process now, without running any teardown code.

    On Windows os._exit still runs DLL detach code, and Qt's teardown there can
    crash while a worker thread is mid-request. TerminateProcess skips it.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        terminate = ctypes.windll.kernel32.TerminateProcess
        terminate.argtypes = (wintypes.HANDLE, wintypes.UINT)
        terminate(wintypes.HANDLE(-1), code & 0xFFFFFFFF)  # -1: this process
    os._exit(code)


if __name__ == "__main__":
    main()
