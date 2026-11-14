"""GUI behaviour, driven headlessly with Qt's offscreen platform."""

import gc
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6 import QtCore, QtGui, QtTest, QtWidgets
except ImportError:  # the GUI is an optional extra
    raise unittest.SkipTest("PySide6 is not installed")

from specprobe import gui
from specprobe.core import parse_endpoints
from tests.mock_api import PETS_SPEC, MockApi

# Never touch the real user's settings.
gui.SETTINGS_ORG = "SpecProbeTests"
gui.SETTINGS_APP = "SpecProbeTests"


def wait_until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("timed out waiting for the UI")
        QtTest.QTest.qWait(10)


def tearDownModule():
    # Free leftover Qt objects on this thread before the interpreter shuts down;
    # PySide6 6.12 can abort when they're left to finalization.
    QtCore.QCoreApplication.sendPostedEvents(None, QtCore.QEvent.DeferredDelete)
    gc.collect()


class GuiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
        cls.api = MockApi().__enter__()
        cls.addClassCleanup(cls.api.__exit__)

    def setUp(self):
        gui._settings().clear()
        self.win = gui.MainWindow()
        self.addCleanup(self._close)

    def _close(self):
        wait_until(lambda: not gui._LIVE_WORKERS, timeout=20)
        self.win.close()
        self.win.deleteLater()
        # processEvents() skips deferred deletes. Left alive, the window would be
        # freed by whichever thread next runs the garbage collector, and destroying
        # a widget on a worker thread crashes.
        QtCore.QCoreApplication.sendPostedEvents(None, QtCore.QEvent.DeferredDelete)
        del self.win
        gc.collect()
        gui._settings().clear()

    def load(self, path="/docs", base=None):
        self.win.url_edit.setEditText((base or self.api.url) + path)
        self.win.load_spec()
        wait_until(lambda: not self.win._busy)

    def select(self, method, path):
        self.win._select_endpoint(method, path)

    def set_param(self, name, value):
        table = self.win.params_table
        for r in range(table.rowCount()):
            if table.item(r, 0).text() == name:
                widget = table.cellWidget(r, 4)
                if widget is not None:
                    widget.setCurrentText(value)
                else:
                    table.item(r, 4).setText(value)
                return
        raise AssertionError(f"no param {name}")

    def param(self, name):
        table = self.win.params_table
        for r in range(table.rowCount()):
            if table.item(r, 0).text() == name:
                return self.win._param_cell_text(r)
        raise AssertionError(f"no param {name}")

    def send(self):
        self.win.send_request()
        wait_until(lambda: not self.win._busy)


class Loading(GuiTestCase):
    def test_starts_empty_with_tls_on_and_no_backend_default(self):
        self.assertEqual(self.win.url_edit.currentText(), "")
        self.assertTrue(self.win.verify_tls.isChecked())
        self.assertFalse(self.win.remember_secrets.isChecked())

    def test_load_fills_tree_and_server(self):
        self.load()
        self.assertEqual(self.win.base_combo.currentText(), self.api.url)
        self.assertGreater(self.win.tree.topLevelItemCount(), 1)
        self.assertTrue(self.win.audit_btn.isEnabled())
        self.assertIn("Pets", self.win.windowTitle())

    def test_spec_auth_scheme_preselected(self):
        self.load()
        self.assertEqual(self.win.auth_kind.currentData(), "bearer")

    def test_failed_load_recovers(self):
        shown = []
        with mock.patch.object(QtWidgets.QMessageBox, "exec", lambda box: shown.append(box.text())):
            self.load(base="http://127.0.0.1:1", path="/x")
        self.assertTrue(shown)
        self.assertTrue(self.win.load_btn.isEnabled())

    def test_malformed_spec_in_worker_does_not_stick(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.json"
            path.write_text("{not json at all", encoding="utf-8")
            shown = []
            with mock.patch.object(QtWidgets.QMessageBox, "exec", lambda box: shown.append(box.text())):
                self.win.url_edit.setEditText(str(path))
                self.win.load_spec()
                wait_until(lambda: not self.win._busy)
        self.assertTrue(shown)

    def test_local_file_needs_a_server(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "spec.json"
            path.write_text(json.dumps(PETS_SPEC), encoding="utf-8")
            self.win.url_edit.setEditText(str(path))
            self.win.load_spec()
            wait_until(lambda: not self.win._busy)
        self.assertEqual(self.win.base_combo.currentText(), "")
        self.select("GET", "/pets")
        warnings = []
        with mock.patch.object(QtWidgets.QMessageBox, "warning", lambda *a: warnings.append(a[2])):
            self.win.send_request()
        self.assertIn("Server URL", warnings[0])
        self.win.base_combo.setEditText(self.api.url)
        self.send()
        self.assertEqual(self.win._last_result.status, 200)

    def test_recent_urls_are_remembered(self):
        self.load()
        self.assertEqual(self.win.url_edit.itemText(0), self.api.url + "/docs")


class Requests(GuiTestCase):
    def setUp(self):
        super().setUp()
        self.load()

    def test_send_get_and_contract_ok(self):
        self.select("GET", "/pets")
        self.send()
        self.assertEqual(self.win._last_result.status, 200)
        self.assertIn("Rex", self.win.pretty_view.toPlainText())
        self.assertIn("contract: OK", self.win.status_label.text())

    def test_contract_mismatch_is_surfaced(self):
        self.select("GET", "/broken")
        self.send()
        self.assertIn("issue", self.win.status_label.text())
        self.assertIn("$.id", self.win.contract_view.toPlainText())
        self.assertIn("Contract (", self.win.resp_tabs.tabText(4))

    def test_missing_path_param_blocks_send(self):
        self.select("GET", "/pets/{id}")
        self.api.server.seen.clear()
        self.win.send_request()
        self.assertFalse(self.win._busy)
        self.assertIn("id", self.win.status_label.text())
        self.assertEqual(self.api.server.seen, [])

    def test_empty_required_cell_is_tinted(self):
        self.select("GET", "/pets/{id}")
        self.assertEqual(self.win.params_table.item(0, 4).background().color().alpha(), 45)
        self.set_param("id", "5")
        self.assertEqual(self.win.params_table.item(0, 4).background().style(), QtCore.Qt.NoBrush)

    def test_url_preview_encodes_and_includes_query(self):
        self.select("GET", "/pets/{id}")
        self.set_param("id", "a/b")
        self.assertTrue(self.win.preview_url_label.text().endswith("/pets/a%2Fb"))

    def test_declared_default_is_prefilled_without_guessing(self):
        self.select("GET", "/pets")
        self.assertEqual(self.param("limit"), "10")
        self.select("GET", "/search/{version}/items")
        self.assertEqual(self.param("version"), "2")
        self.assertEqual(self.param("q"), "")

    def test_header_and_cookie_params_are_sent(self):
        self.select("GET", "/echo")
        self.set_param("X-Trace", "abc")
        self.set_param("sid", "s1")
        self.send()
        headers = self.win._last_result.json["headers"]
        self.assertEqual(headers["x-trace"], "abc")
        self.assertIn("sid=s1", headers["cookie"])

    def test_extra_headers_are_sent(self):
        self.win._add_header_row("X-Tenant", "acme")
        self.select("GET", "/echo")
        self.send()
        self.assertEqual(self.win._last_result.json["headers"]["x-tenant"], "acme")

    def test_body_content_type_choices(self):
        self.select("POST", "/echo")
        choices = [self.win.content_type.itemText(i) for i in range(self.win.content_type.count())]
        self.assertIn("multipart/form-data", choices)
        self.assertEqual(self.win.content_type.currentText(), "application/json")
        self.win.insert_example_body()
        self.assertIn("from-media-example", self.win.body_edit.toPlainText())
        self.win.content_type.setCurrentText("text/plain")
        self.win.body_edit.setPlainText("raw text")
        self.send()
        self.assertEqual(self.win._last_result.json["body"], "raw text")
        self.assertEqual(self.win._last_result.json["headers"]["content-type"], "text/plain")

    def test_invalid_json_body_is_rejected_before_sending(self):
        self.select("POST", "/echo")
        self.win.body_edit.setPlainText("{oops")
        warnings = []
        with mock.patch.object(QtWidgets.QMessageBox, "warning", lambda *a: warnings.append(a[2])):
            self.win.send_request()
        self.assertFalse(self.win._busy)
        self.assertIn("JSON", warnings[0])

    def test_binary_response_and_save(self):
        self.select("GET", "/binary")
        self.send()
        self.assertIn("binary response", self.win.pretty_view.toPlainText())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out"
            self.win.write_response(str(path))
            self.assertEqual(path.read_bytes(), b"\x89PNG\x00\x01\x02")

    def test_error_status_is_red(self):
        self.select("GET", "/boom")
        self.send()
        self.assertIn(gui.BAD_COLOR, self.win.status_label.text())

    def test_connection_failure_is_shown(self):
        self.select("GET", "/pets")
        self.win.base_combo.setEditText("http://127.0.0.1:1")
        self.send()
        self.assertIn("ERROR", self.win.status_label.text())
        self.assertFalse(self.win.save_resp_btn.isEnabled())

    def test_cancel_ignores_late_result(self):
        self.select("GET", "/slow")
        self.win.send_request()
        self.assertTrue(self.win.cancel_btn.isEnabled())
        self.win.cancel_request()
        self.assertFalse(self.win._busy)
        self.assertTrue(self.win.send_btn.isEnabled())
        wait_until(lambda: not gui._LIVE_WORKERS, timeout=10)
        QtTest.QTest.qWait(50)
        self.assertIn("Cancelled", self.win.status_label.text())
        self.assertEqual(self.win.pretty_view.toPlainText(), "")

    def test_copy_curl(self):
        self.win.token_edit.setText("good")
        self.select("GET", "/secure")
        self.win.copy_curl()
        text = QtGui.QGuiApplication.clipboard().text()
        self.assertIn("curl -X GET", text)
        self.assertIn("Authorization: Bearer good", text)

    def test_large_response_skips_highlighting(self):
        view = self.win.pretty_view
        self.win._set_large_text(view, "x" * (gui.MAX_HIGHLIGHT_CHARS + 1), self.win._pretty_highlighter)
        self.assertIsNone(self.win._pretty_highlighter.document())
        self.win._set_large_text(view, "{}", self.win._pretty_highlighter)
        self.assertIsNotNone(self.win._pretty_highlighter.document())
        self.win._set_large_text(view, "y" * (gui.MAX_DISPLAY_CHARS + 5))
        self.assertIn("display truncated", view.toPlainText())


class Drafts(GuiTestCase):
    def setUp(self):
        super().setUp()
        self.load()

    def test_edits_survive_switching_endpoints(self):
        self.select("POST", "/echo")
        self.win.body_edit.setPlainText('{"kept": true}')
        self.select("GET", "/pets")
        self.set_param("limit", "99")
        self.select("POST", "/echo")
        self.assertEqual(self.win.body_edit.toPlainText(), '{"kept": true}')
        self.select("GET", "/pets")
        self.assertEqual(self.param("limit"), "99")

    def test_path_value_carries_within_a_prefix_only(self):
        self.select("GET", "/pets/{id}")
        self.set_param("id", "42")
        self.select("DELETE", "/pets/{id}")
        self.assertEqual(self.param("id"), "42")  # same resource
        spec = {"paths": {"/a/{id}": {"get": {}}, "/b/{id}": {"delete": {}}}}
        self.win.spec = spec
        self.win.endpoints = parse_endpoints(spec)
        self.win.populate_tree()
        self.win.current_endpoint = None
        self.select("GET", "/a/{id}")
        self.set_param_path("/a/{id}", "7")
        self.select("DELETE", "/b/{id}")
        self.assertEqual(self.win._param_values(), {})  # undeclared here, and nothing inherited
        self.assertEqual(self.win.preview_url_label.text().rsplit("/", 1)[1], "{id}")

    def set_param_path(self, path, value):
        self.win._sticky_path_values[self.win._sticky_key(path, "id")] = value

    def test_history_restores_request_and_response(self):
        self.select("GET", "/pets")
        self.set_param("limit", "3")
        self.send()
        self.select("GET", "/boom")
        self.send()
        self.assertEqual(self.win.history_list.count(), 2)
        self.win.history_list.setCurrentRow(1)
        self.assertEqual(self.win.current_endpoint.path, "/pets")
        self.assertEqual(self.param("limit"), "3")
        self.assertIn("Rex", self.win.pretty_view.toPlainText())


class Credentials(GuiTestCase):
    def test_each_auth_kind_reaches_the_server(self):
        self.load()
        self.select("GET", "/secure")
        self.win._set_auth_kind("bearer")
        self.win.token_edit.setText("good")
        self.send()
        self.assertEqual(self.win._last_result.json["who"], "bearer")
        self.win._set_auth_kind("basic")
        self.win.basic_user.setText("ann")
        self.win.basic_pass.setText("pw")
        self.send()
        self.assertEqual(self.win._last_result.json["who"], "basic")
        self.win._set_auth_kind("apikey")
        self.win.apikey_name.setText("X-Key")
        self.win.apikey_value.setText("k1")
        self.send()
        self.assertEqual(self.win._last_result.json["who"], "apikey")
        self.win._set_auth_kind("none")
        self.send()
        self.assertEqual(self.win._last_result.status, 401)

    def test_request_tab_hides_credentials(self):
        self.load()
        self.select("GET", "/secure")
        self.win.token_edit.setText("good")
        self.send()
        self.assertNotIn("good", self.win.request_view.toPlainText())
        self.assertIn("hidden", self.win.request_view.toPlainText())

    def test_token_is_not_saved_by_default(self):
        self.load()
        self.win.token_edit.setText("SECRET-TOKEN")
        self.win._store_profile()
        self.assertNotIn("SECRET-TOKEN", json.dumps(gui.load_profile(self.win._profile_key)))
        self.assertEqual(gui._settings().value("main/token", "", str), "")

    def test_remember_is_opt_in_and_restores(self):
        self.load()
        self.win.remember_secrets.setChecked(True)
        self.win.token_edit.setText("KEPT")
        key = self.win._profile_key
        self.win._store_profile()
        self.assertEqual(gui.load_profile(key)["secrets"]["token"], "KEPT")
        self.win.remember_secrets.setChecked(False)
        self.win._store_profile()
        self.assertNotIn("secrets", gui.load_profile(key))

    def test_legacy_plaintext_token_is_removed(self):
        s = gui._settings()
        s.setValue("main/token", "OLD-TOKEN")
        s.setValue("login/auth_url", "http://old/")
        s.sync()
        win = gui.MainWindow()
        self.addCleanup(win.deleteLater)
        self.addCleanup(win.close)
        self.assertFalse(gui._settings().contains("main/token"))
        self.assertFalse(gui._settings().contains("login/auth_url"))
        self.assertEqual(win.token_edit.text(), "")

    def test_credentials_do_not_follow_to_another_api(self):
        self.load()
        self.win.token_edit.setText("FOR-API-ONE")
        self.win.session_cookies = {"sid": "1"}
        other = self.api.url.replace("127.0.0.1", "localhost")
        self.load(base=other)
        self.assertEqual(self.win.token_edit.text(), "")
        self.assertEqual(self.win.session_cookies, {})
        self.assertEqual(self.win.base_combo.currentText(), other)

    def test_settings_are_per_api(self):
        self.load()
        self.win._add_header_row("X-One", "1")
        self.win._profile["login"] = {"auth_url": self.api.url + "/login"}
        other = self.api.url.replace("127.0.0.1", "localhost")
        self.load(base=other)
        self.assertEqual(self.win.extra_headers(), {})
        self.assertNotIn("login", self.win._profile)
        self.load()
        self.assertEqual(self.win.extra_headers(), {"X-One": "1"})
        self.assertIn("login", self.win._profile)

    def test_warns_when_requests_leave_the_spec_host(self):
        self.load()
        self.win.token_edit.setText("t")
        self.assertTrue(self.win.base_warning.isHidden())
        self.win.base_combo.setEditText("https://elsewhere.example")
        self.assertFalse(self.win.base_warning.isHidden())
        self.assertIn("elsewhere.example", self.win.base_warning.text())

    def test_cookie_session_is_used_and_cleared(self):
        self.load()
        self.win._set_auth_kind("none")
        self.select("GET", "/secure")
        self.win.session_cookies = {"sessionid": "abc"}
        self.send()
        self.assertEqual(self.win._last_result.json["who"], "cookie")
        self.win.clear_credentials()
        self.assertEqual(self.win.session_cookies, {})


class UntrustedContent(GuiTestCase):
    PAYLOAD = "<img src=x onerror=alert(1)><b>bold</b>"

    def test_spec_text_is_escaped_or_plain(self):
        spec = {"paths": {"/x": {"get": {"summary": self.PAYLOAD, "description": self.PAYLOAD,
                                         "parameters": [{"name": "q", "in": "query", "description": self.PAYLOAD}],
                                         "responses": {"200": {"description": self.PAYLOAD}}}}}}
        self.win.spec = spec
        self.win.spec_url = "http://h/s.json"
        self.win.endpoints = parse_endpoints(spec)
        self.win.populate_tree()
        self.select("GET", "/x")
        self.assertEqual(self.win.summary_label.textFormat(), QtCore.Qt.PlainText)
        self.assertEqual(self.win.path_label.textFormat(), QtCore.Qt.PlainText)
        self.assertNotIn("<img", self.win.docs_view.toHtml())
        self.assertIn(self.PAYLOAD, self.win.docs_view.toPlainText())
        tip = self.win.tree.topLevelItem(0).child(0).toolTip(0)
        self.assertNotIn("<img", tip)
        self.assertNotIn("<img", self.win.params_table.item(0, 5).toolTip())

    def test_server_text_is_escaped_in_status(self):
        from specprobe.core import CallResult

        result = CallResult("GET", "http://h/" + self.PAYLOAD, 200, self.PAYLOAD, 1, {}, "x")
        self.win._show_result(result, [], note=self.PAYLOAD)
        self.assertNotIn("<img", self.win.status_label.text())
        self.win._show_failure(self.PAYLOAD)
        self.assertNotIn("<img", self.win.status_label.text())


class Login(GuiTestCase):
    def dialog(self):
        return gui.LoginDialog(self.win, self.api.url, False, spec=PETS_SPEC,
                               endpoints=parse_endpoints(PETS_SPEC))

    def submit(self, dlg):
        dlg.do_login()
        wait_until(lambda: dlg.login_btn.isEnabled())

    def test_prefills_from_spec(self):
        dlg = self.dialog()
        self.assertEqual(dlg.auth_url.currentText(), self.api.url + "/login")
        self.assertEqual(dlg.field_name.currentText(), "email")
        self.assertEqual(list(dlg._extra_fields()), ["device_id"])

    def test_no_default_button_can_ever_fire(self):
        dlg = self.dialog()
        dlg.show()
        for btn in dlg.findChildren(QtWidgets.QPushButton):
            self.assertFalse(btn.isDefault(), btn.text())
            self.assertFalse(btn.autoDefault(), btn.text())
        dlg.username.setText("a")
        dlg.password.setText("pw")
        dlg.extra_table.setFocus()
        QtTest.QTest.keyClick(dlg.extra_table, QtCore.Qt.Key_Return)
        QtTest.QTest.qWait(50)
        self.assertIsNone(dlg._worker)
        dlg.close()

    def test_enter_in_password_submits(self):
        dlg = self.dialog()
        dlg.show()
        dlg.username.setText("a@b")
        dlg.password.setText("pw")
        dlg.extra_table.item(0, 1).setText("d1")
        QtTest.QTest.keyClick(dlg.password, QtCore.Qt.Key_Return)
        wait_until(lambda: dlg.token is not None)
        self.assertEqual(dlg.token, "a-token")

    def test_requires_credentials_and_path(self):
        dlg = self.dialog()
        dlg.do_login()
        self.assertIn("required", dlg.status.text())
        dlg.username.setText("a")
        dlg.password.setText("b")
        dlg.auth_url.setEditText(self.api.url + "/")
        dlg.do_login()
        self.assertIn("login path", dlg.status.text())

    def test_advanced_body_needs_no_username_fields(self):
        dlg = self.dialog()
        dlg.advanced_toggle.setChecked(True)
        dlg.body_edit.setPlainText('{"email": "x", "password": "pw", "device_id": "d"}')
        self.submit(dlg)
        self.assertEqual(dlg.token, "a-token")

    def test_validation_errors_offer_fixes(self):
        dlg = gui.LoginDialog(self.win, self.api.url, False)
        dlg.auth_url.setEditText(self.api.url + "/login")
        dlg.username.setText("a")
        dlg.password.setText("pw")
        self.submit(dlg)
        self.assertIn("email", dlg.status.text())
        self.assertFalse(dlg.add_missing_btn.isHidden())
        dlg._add_missing_fields()
        self.assertEqual(list(dlg._extra_fields()), ["device_id"])

    def test_server_text_escaped_in_status(self):
        dlg = gui.LoginDialog(self.win, self.api.url, False)
        from specprobe.core import LoginResult
        dlg._on_login_done(LoginResult(None, 400, {"<img src=x>": ["<b>y</b>"]}))
        self.assertNotIn("<img", dlg.status.text())
        self.assertNotIn("<img", dlg.add_missing_btn.text().replace("<img src=x>", "") + dlg.status.text())

    def test_token_flows_to_main_window(self):
        self.load()

        def fake_exec(dlg):
            dlg.username.setText("a@b")
            dlg.password.setText("pw")
            dlg.extra_table.item(0, 1).setText("d1")
            dlg.do_login()
            wait_until(lambda: dlg.token is not None)
            return QtWidgets.QDialog.Accepted

        with mock.patch.object(gui.LoginDialog, "exec", fake_exec):
            self.win.open_login()
        self.assertEqual(self.win.token_edit.text(), "a-token")
        self.assertEqual(self.win.auth_kind.currentData(), "bearer")
        remembered = gui.load_profile(self.win._profile_key)["login"]
        self.assertEqual(remembered["field"], "email")
        self.assertNotIn("password", remembered)

    def test_closing_dialog_mid_request_is_safe(self):
        dlg = self.dialog()
        dlg.username.setText("a")
        dlg.password.setText("pw")
        dlg.do_login()
        dlg.reject()
        dlg.deleteLater()
        wait_until(lambda: not gui._LIVE_WORKERS)
        QtTest.QTest.qWait(20)


class Audit(GuiTestCase):
    def test_runs_and_exports(self):
        self.load()
        dlg = gui.AuditDialog(self.win)
        dlg.params_edit.setText("id=5, q=x")
        dlg.start()
        wait_until(lambda: dlg.start_btn.isEnabled(), timeout=20)
        rows = {dlg.table.item(r, 4).text(): dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())}
        self.assertEqual(rows["GET /pets/{id}"], "ok")
        self.assertEqual(rows["GET /boom"], "server")
        self.assertIn("contract issues", dlg.summary.text())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "a.json"
            dlg.write_report(str(path))
            self.assertTrue(json.loads(path.read_text(encoding="utf-8"))["results"])

    def test_skips_when_values_unknown(self):
        self.load()
        dlg = gui.AuditDialog(self.win)
        dlg.tag_combo.setCurrentText("pets")
        dlg.start()
        wait_until(lambda: dlg.start_btn.isEnabled(), timeout=20)
        rows = {dlg.table.item(r, 4).text(): dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())}
        self.assertEqual(rows["GET /pets/{id}"], "skip")

    def test_stop(self):
        self.load()
        dlg = gui.AuditDialog(self.win)
        dlg.start()
        dlg.stop()
        wait_until(lambda: dlg.start_btn.isEnabled(), timeout=20)
        self.assertLessEqual(len(dlg._rows), 2)


class LogTab(GuiTestCase):
    def test_trace_appears_and_hides_secrets(self):
        self.load()
        self.select("GET", "/echo")
        self.win._set_auth_kind("apikey")
        self.win.apikey_name.setText("api_key")
        self.win.apikey_location.setCurrentText("query")
        self.win.apikey_value.setText("TOPSECRET")
        self.send()
        QtTest.QTest.qWait(20)
        text = self.win.log_view.toPlainText()
        self.assertIn("execute_call", text)
        self.assertNotIn("TOPSECRET", text)
        self.assertNotIn("TOPSECRET", self.win.status_label.text())


class Highlighting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    def colors(self, text):
        doc = QtGui.QTextDocument(text)
        highlighter = gui.JsonHighlighter(doc)
        highlighter.rehighlight()  # normally deferred to the event loop
        block = doc.firstBlock()
        return {
            text[r.start:r.start + r.length]: r.format.foreground().color().name()
            for r in block.layout().formats()
        }

    def test_key_and_value_on_one_line(self):
        colors = self.colors('"type": "missing"')
        self.assertEqual(colors['"type"'], "#a855f7")
        self.assertEqual(colors['"missing"'], gui.OK_COLOR)

    def test_numbers_and_keywords_inside_strings_stay_strings(self):
        colors = self.colors('"a1": "true 42", "n": 42, "b": true')
        self.assertEqual(colors['"true 42"'], gui.OK_COLOR)
        self.assertEqual(colors["42"], gui.WARN_COLOR)
        self.assertEqual(colors["true"], "#3b82f6")


class Theme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    def tearDown(self):
        self.app.styleHints().unsetColorScheme()
        QtWidgets.QApplication.setPalette(QtGui.QPalette())

    def scheme(self, scheme):
        return mock.patch.object(self.app.styleHints(), "colorScheme", return_value=scheme)

    def test_dark_alternate_base_is_a_grey_near_base(self):
        # Windows' dark palette has a navy AlternateBase, which Fusion uses for unticked checkboxes.
        role = QtGui.QPalette.ColorRole
        with self.scheme(QtCore.Qt.ColorScheme.Dark):
            gui.neutral_alternate_base()
        pal = self.app.palette()
        alt, base = pal.color(role.AlternateBase), pal.color(role.Base)
        self.assertTrue(pal.isBrushSet(QtGui.QPalette.Active, role.AlternateBase))
        self.assertLess(abs(alt.red() - base.red()) + abs(alt.blue() - base.blue()), 60, alt.name())
        self.assertLess(abs(alt.red() - alt.blue()), 12, alt.name())

    def test_light_keeps_the_system_palette(self):
        with self.scheme(QtCore.Qt.ColorScheme.Dark):
            gui.neutral_alternate_base()
        with self.scheme(QtCore.Qt.ColorScheme.Light):
            gui.neutral_alternate_base()
        self.assertEqual(self.app.palette().resolveMask(), 0)


class Shutdown(unittest.TestCase):
    """Closing during a request must not crash: Qt aborts if a running QThread is destroyed."""

    SCRIPT = """
import sys
from PySide6 import QtCore
from specprobe import gui
gui.SETTINGS_ORG = gui.SETTINGS_APP = "SpecProbeTests"
URL = sys.argv[1]

class Win(gui.MainWindow):
    def __init__(self):
        super().__init__()
        self.url_edit.setEditText(URL)
        self.load_spec()
        self.poll = QtCore.QTimer(self)
        self.poll.timeout.connect(self.step)
        self.poll.start(20)

    def step(self):
        if not self.endpoints:
            return
        if self.current_endpoint is None:
            self._select_endpoint("GET", "/slow")
            self.send_request()
        else:
            print("closing with live workers:", len(gui._LIVE_WORKERS), flush=True)
            self.poll.stop()
            self.close()

gui.MainWindow = Win
sys.argv = sys.argv[:1]
gui.main()
"""

    def test_quit_while_a_request_is_running(self):
        import subprocess
        import sys

        root = Path(gui.__file__).parent.parent
        env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "PYTHONPATH": str(root)}
        with MockApi() as api:
            done = subprocess.run(
                [sys.executable, "-c", self.SCRIPT, api.url + "/openapi.json"],
                env=env, capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("closing with live workers: 1", done.stdout, done.stderr)
        self.assertNotIn("QThread", done.stderr)


class ProfileKeys(unittest.TestCase):
    def test_keys(self):
        self.assertEqual(gui.profile_key("https://API.example.com:8443/docs"), "api.example.com%3A8443")
        self.assertEqual(gui.profile_key("localhost:8000/x"), "localhost%3A8000")
        self.assertEqual(gui.profile_key(""), "")


if __name__ == "__main__":
    unittest.main()
