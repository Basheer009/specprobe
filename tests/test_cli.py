import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from specprobe import cli
from tests.mock_api import PETS_SPEC, MockApi


def run(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if stdin is not None:
            with mock.patch("sys.stdin", io.StringIO(stdin)):
                try:
                    code = cli.main(list(argv))
                except SystemExit as e:
                    code = e.code
        else:
            try:
                code = cli.main(list(argv))
            except SystemExit as e:
                code = e.code
    return code, out.getvalue(), err.getvalue()


class CliTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = MockApi().__enter__()
        cls.addClassCleanup(cls.api.__exit__)

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("SPECPROBE_TOKEN", "SPECPROBE_URL", "SPECPROBE_PASSWORD", "MSYSTEM"):
            os.environ.pop(name, None)

    def cli(self, *argv, **kwargs):
        return run("--url", self.api.url + "/docs", *argv, **kwargs)


class Spec(CliTestCase):
    def test_json_output_is_clean_on_stdout(self):
        code, out, err = self.cli("spec")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["info"]["title"], "Pets")
        self.assertEqual(payload["spec_version"], "OpenAPI 3.0.3")
        self.assertEqual(err, "")  # quiet unless -v

    def test_filters_apply_to_json_too(self):
        _, out, _ = self.cli("spec", "--filter", "secure")
        self.assertEqual([e["path"] for e in json.loads(out)["endpoints"]], ["/secure"])
        _, out, _ = self.cli("spec", "--method", "delete")
        self.assertEqual([e["path"] for e in json.loads(out)["endpoints"]], ["/pets/{id}"])

    def test_table(self):
        code, out, _ = self.cli("spec", "--table", "--tag", "auth")
        self.assertEqual(code, 0)
        self.assertIn("# auth: bearerAuth (bearer)", out)
        self.assertIn("/secure", out)
        self.assertNotIn("/pets", out)

    def test_local_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "spec.json"
            path.write_text(json.dumps(PETS_SPEC), encoding="utf-8")
            code, out, _ = run("--url", str(path), "spec")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["base_url"], "")
            code, _, err = run("--url", str(path), "call", "--method", "GET", "--path", "/pets")
            self.assertEqual(code, 2)
            self.assertIn("--base", err)
            code, out, _ = run("--url", str(path), "--base", self.api.url, "call", "--method", "GET", "--path", "/pets")
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)["status"], 200)

    def test_url_from_environment_and_required_otherwise(self):
        code, _, err = run("spec")
        self.assertEqual(code, 2)
        self.assertIn("--url", err)
        os.environ["SPECPROBE_URL"] = self.api.url + "/docs"
        # argparse reads the default when the parser is built.
        code, _, _ = run("spec")
        self.assertEqual(code, 0)

    def test_load_failure_is_json_on_stderr(self):
        code, out, err = run("--url", "http://127.0.0.1:1/x", "spec")
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertIn("error", json.loads(err))

    def test_verbose_traces_to_stderr_only(self):
        code, out, err = self.cli("-v", "spec")
        self.assertEqual(code, 0)
        json.loads(out)
        self.assertIn("[specprobe] fetch_spec", err)


class Show(CliTestCase):
    def test_show(self):
        code, out, _ = self.cli("show", "--method", "get", "--path", "/pets")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["params"][0]["default"], "10")
        self.assertEqual(payload["responses"]["200"]["example"][0]["name"], "string")

    def test_unknown_endpoint(self):
        code, _, err = self.cli("show", "--method", "GET", "--path", "/nope")
        self.assertEqual(code, 2)
        self.assertIn("isn't in this spec", err)


class Call(CliTestCase):
    def test_simple_get(self):
        code, out, _ = self.cli("call", "--method", "GET", "--path", "/pets")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["body"][0]["name"], "Rex")

    def test_error_status_exits_1(self):
        code, out, _ = self.cli("call", "--method", "GET", "--path", "/boom")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["status"], 500)

    def test_missing_path_param_stops_before_sending(self):
        code, _, err = self.cli("call", "--method", "GET", "--path", "/pets/{id}")
        self.assertEqual(code, 2)
        self.assertIn("--path-param", err)

    def test_declared_path_default_is_used(self):
        code, out, err = self.cli("call", "--method", "GET", "--path", "/search/{version}/items", "--query", "q=a")
        self.assertEqual(code, 0, err)
        self.assertIn("/search/2/items?q=a", json.loads(out)["url"])

    def test_repeated_query_flags_all_sent(self):
        code, out, _ = self.cli("call", "--method", "GET", "--path", "/echo", "--query", "a=1", "--query", "a=2")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["body"]["query"]["a"], ["1", "2"])

    def test_array_param_uses_declared_serialisation(self):
        _, out, _ = self.cli("call", "--method", "GET", "--path", "/pets", "--query", "tags=x,y", "--curl")
        self.assertIn("tags=x&tags=y", out)

    def test_bad_kv_is_usage_error(self):
        code, _, err = self.cli("call", "--method", "GET", "--path", "/pets", "--query", "noequals")
        self.assertEqual(code, 2)
        self.assertIn("name=value", err)

    def test_bad_json_is_usage_error(self):
        code, _, err = self.cli("call", "--method", "POST", "--path", "/echo", "--json-body", "{oops")
        self.assertEqual(code, 2)
        self.assertIn("isn't valid JSON", err)

    def test_undocumented_path_warns_and_sends(self):
        code, out, err = self.cli("call", "--method", "GET", "--path", "/echo2")
        self.assertIn("isn't in the spec", err)
        self.assertEqual(json.loads(out)["status"], 404)
        self.assertEqual(code, 1)

    def test_json_file_is_relative_to_caller(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "b.json"
            path.write_text('{"a": "x"}', encoding="utf-8")
            old = os.getcwd()
            os.chdir(d)
            try:
                code, out, _ = self.cli("call", "--method", "POST", "--path", "/echo", "--json-file", "b.json")
            finally:
                os.chdir(old)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(json.loads(out)["body"]["body"]), {"a": "x"})

    def test_example_body(self):
        _, out, _ = self.cli("call", "--method", "POST", "--path", "/echo", "--example")
        self.assertEqual(json.loads(json.loads(out)["body"]["body"]), {"a": "from-media-example"})

    def test_form_and_upload(self):
        _, out, _ = self.cli("call", "--method", "POST", "--path", "/echo", "--form", "a=1", "--form", "a=2")
        self.assertEqual(json.loads(out)["body"]["body"], "a=1&a=2")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "u.bin"
            path.write_bytes(b"BYTES")
            _, out, _ = self.cli("call", "--method", "POST", "--path", "/echo", "--form", f"f=@{path}")
        echoed = json.loads(out)["body"]
        self.assertIn("multipart/form-data", echoed["headers"]["content-type"])
        self.assertIn("BYTES", echoed["body"])

    def test_raw_text_body(self):
        _, out, _ = self.cli("call", "--method", "POST", "--path", "/echo", "--body", "hello",
                             "--content-type", "text/plain")
        self.assertEqual(json.loads(out)["body"]["body"], "hello")

    def test_raw_flag(self):
        code, out, _ = self.cli("call", "--method", "GET", "--path", "/pets", "--raw")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)[0]["name"], "Rex")

    def test_binary_output_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.png"
            code, out, _ = self.cli("call", "--method", "GET", "--path", "/binary", "--output", str(path))
            self.assertEqual(code, 0)
            self.assertEqual(path.read_bytes(), b"\x89PNG\x00\x01\x02")
            self.assertIn("binary", json.loads(out)["body"])

    def test_validate(self):
        code, out, _ = self.cli("call", "--method", "GET", "--path", "/broken", "--validate")
        self.assertEqual(code, 1)
        self.assertTrue(json.loads(out)["contract_issues"])
        code, out, _ = self.cli("call", "--method", "GET", "--path", "/pets", "--validate")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["contract_issues"], [])

    def test_curl_does_not_send(self):
        before = len(self.api.server.seen)
        code, out, _ = run("--url", self.api.url + "/docs", "--token", "t", "call",
                           "--method", "GET", "--path", "/secure", "--curl")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("curl -X GET"))
        self.assertIn("Authorization: Bearer t", out)
        self.assertFalse(any("/secure" in s for s in self.api.server.seen[before:]))

    def test_msys_mangled_path_is_explained(self):
        os.environ["MSYSTEM"] = "MINGW64"
        code, _, err = self.cli("call", "--method", "GET", "--path", "C:/Program Files/Git/pets")
        self.assertEqual(code, 2)
        self.assertIn("MSYS_NO_PATHCONV", err)

    def test_double_slash_workaround_is_accepted(self):
        code, out, _ = self.cli("call", "--method", "GET", "--path", "//pets")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["status"], 200)

    def test_non_ascii_response(self):
        code, out, _ = self.cli("call", "--method", "POST", "--path", "/echo", "--json-body", '{"a": "مرحبا"}')
        self.assertEqual(code, 0)
        self.assertIn("مرحبا", out)


class AuthFlags(CliTestCase):
    def secure(self, *flags):
        return run("--url", self.api.url + "/docs", *flags, "call", "--method", "GET", "--path", "/secure")

    def test_flags(self):
        self.assertEqual(self.secure()[0], 1)
        self.assertEqual(json.loads(self.secure("--token", "good")[1])["body"]["who"], "bearer")
        self.assertEqual(json.loads(self.secure("--token", "good", "--token-prefix", "Token")[1])["body"]["who"], "bearer")
        self.assertEqual(json.loads(self.secure("--basic", "ann:pw")[1])["body"]["who"], "basic")
        self.assertEqual(json.loads(self.secure("--api-key", "X-Key=k1")[1])["body"]["who"], "apikey")
        self.assertEqual(json.loads(self.secure("--api-key", "key=k1", "--api-key-in", "query")[1])["body"]["who"], "apikey")
        self.assertEqual(json.loads(self.secure("--cookie", "sessionid=abc")[1])["body"]["who"], "cookie")

    def test_token_from_environment(self):
        os.environ["SPECPROBE_TOKEN"] = "good"
        self.assertEqual(self.secure()[0], 0)

    def test_foreign_server_warns_when_credentials_are_present(self):
        with tempfile.TemporaryDirectory() as d:
            spec = dict(PETS_SPEC, servers=[{"url": "http://127.0.0.1:1"}])
            path = Path(d) / "s.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            with mock.patch.object(cli, "fetch_spec", return_value=(spec, self.api.url + "/s.json")):
                _, _, err = run("--url", "x", "--token", "t", "call", "--method", "GET",
                                "--path", "/pets", "--timeout", "1")
        self.assertIn("different host", err)


class Login(CliTestCase):
    def login(self, *argv, **kwargs):
        return self.cli("login", "--username", "a", *argv, **kwargs)

    def test_token_only_from_stdin_password(self):
        code, out, _ = self.login("--auth-path", "/login", "--username-field", "email",
                                  "--extra", "device_id=d", "--password-stdin", "--token-only", stdin="pw\n")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "a-token")

    def test_password_from_environment(self):
        os.environ["SPECPROBE_PASSWORD"] = "pw"
        code, _, _ = self.login("--auth-path", "/oauth/token", "--form")
        self.assertEqual(code, 0)

    def test_no_password_when_not_interactive(self):
        code, _, err = self.login("--auth-path", "/login", stdin="")
        self.assertEqual(code, 2)
        self.assertIn("No password", err)

    def test_field_errors_are_reported(self):
        code, out, _ = self.login("--auth-path", "/login", "--password", "pw")
        self.assertEqual(code, 2)
        self.assertEqual(sorted(json.loads(out)["field_errors"]), ["device_id", "email"])

    def test_cookie_session(self):
        code, out, _ = self.login("--auth-path", "/cookie-login", "--password", "x")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["cookies"], {"sessionid": "abc"})
        code, _, err = self.login("--auth-path", "/cookie-login", "--password", "x", "--token-only")
        self.assertEqual(code, 2)
        self.assertIn("cookie session", err)

    def test_token_path(self):
        code, out, _ = self.login("--auth-path", "/custom-login", "--password", "x",
                                  "--token-path", "payload.weird_name", "--token-only")
        self.assertEqual((code, out.strip()), (0, "custom-token"))


class Audit(CliTestCase):
    def test_jobs_gives_the_same_report(self):
        _, one, _ = self.cli("audit", "--param", "id=1")
        code, many, _ = self.cli("audit", "--param", "id=1", "--jobs", "4")
        self.assertEqual(code, 0)
        strip = lambda out: [(r["path"], r["status"]) for r in json.loads(out)["results"]]
        self.assertEqual(strip(one), strip(many))

    def test_jobs_must_be_positive(self):
        code, _, err = self.cli("audit", "--jobs", "0")
        self.assertEqual(code, 2)
        self.assertIn("between 1 and 64", err)

    def test_report_and_buckets(self):
        code, out, err = self.cli("audit")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        by_path = {r["path"]: r for r in payload["results"]}
        self.assertEqual(by_path["/pets"]["bucket"], "ok")
        self.assertEqual(by_path["/secure"]["bucket"], "auth")
        self.assertEqual(by_path["/boom"]["bucket"], "server")
        self.assertEqual(by_path["/undocumented"]["bucket"], "client")
        self.assertIn({"method": "GET", "path": "/pets/{id}", "missing": ["id"]}, payload["skipped"])
        self.assertIn("auditing", err)

    def test_params(self):
        _, out, _ = self.cli("audit", "--param", "id=5", "--param", "q=x")
        by_path = {r["path"]: r for r in json.loads(out)["results"]}
        self.assertEqual(by_path["/pets/{id}"]["bucket"], "ok")
        self.assertEqual(by_path["/search/{version}/items"]["bucket"], "ok")

    def test_fail_on(self):
        self.assertEqual(self.cli("audit", "--tag", "pets")[0], 0)
        self.assertEqual(self.cli("audit", "--tag", "contract", "--fail-on", "server")[0], 1)
        self.assertEqual(self.cli("audit", "--tag", "auth", "--fail-on", "server")[0], 0)
        self.assertEqual(self.cli("audit", "--tag", "auth", "--fail-on", "any")[0], 1)

    def test_validate_counts_contract_problems(self):
        code, out, _ = self.cli("audit", "--filter", "/broken", "--validate", "--fail-on", "server")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["contract_problems"], 1)

    def test_table_and_limit(self):
        code, out, _ = self.cli("audit", "--table", "--limit", "1")
        self.assertEqual(code, 0)
        self.assertEqual(sum(1 for line in out.splitlines() if " GET " in line and not line.startswith("skip")), 1)

    def test_never_sends_anything_but_get(self):
        self.api.server.seen.clear()
        self.cli("audit", "--param", "id=1", "--param", "q=x")
        # do_POST and do_DELETE would record /echo bodies or 204s; only GET paths appear.
        self.assertNotIn("/login", self.api.server.seen)
        self.assertNotIn("/login/refresh", self.api.server.seen)


class Misc(unittest.TestCase):
    def test_version(self):
        code, out, _ = run("--version")
        self.assertEqual(code, 0)
        self.assertIn("specprobe", out)


if __name__ == "__main__":
    unittest.main()
