import json
import tempfile
import time
import unittest
from pathlib import Path

import requests

from specprobe import core
from specprobe.core import (
    Auth,
    audit_one,
    build_url,
    discover_spec_url,
    example_body,
    example_from_schema,
    execute_call,
    extract_field_errors,
    extract_token,
    fetch_spec,
    find_endpoint,
    find_login_candidates,
    guess_login_shape,
    login,
    normalize_url,
    parse_endpoints,
    parse_security_schemes,
    plan_audit,
    redact_url,
    run_audit,
    server_urls,
    split_param_values,
    to_curl,
    validate_response,
    validate_schema,
)
from tests.mock_api import PETS_SPEC, SWAGGER2_SPEC, MockApi


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = MockApi().__enter__()
        cls.addClassCleanup(cls.api.__exit__)


class Discovery(ApiTestCase):
    def assert_finds(self, path, title):
        spec, found = fetch_spec(self.api.url + path)
        self.assertEqual(spec["info"]["title"], title, found)
        return found

    def test_direct_spec_url_without_a_known_name(self):
        self.assertTrue(self.assert_finds("/custom/spec-location", "Pets").endswith("/custom/spec-location"))

    def test_fastapi_docs_page_names_the_spec(self):
        self.assertTrue(self.assert_finds("/docs", "Pets").endswith("/openapi.json"))

    def test_redoc_page(self):
        self.assertTrue(self.assert_finds("/redoc", "Pets").endswith("/openapi.json"))

    def test_swashbuckle_index_script(self):
        self.assertTrue(self.assert_finds("/swagger/index.html", "Legacy").endswith("/swagger/v1/swagger.json"))

    def test_springdoc_config_url(self):
        self.assertTrue(self.assert_finds("/swagger-ui/index.html", "Pets").endswith("/v3/api-docs"))

    def test_initializer_holding_the_url_in_a_variable(self):
        # Shape of the real swagger-initializer.js on the Swagger project's own sites.
        found = self.assert_finds("/hosted-ui/", "Pets")
        self.assertTrue(found.endswith("/hosted-ui/api/v3/openapi.json"), found)

    def test_swagger_ui_express_embedded_spec(self):
        found = self.assert_finds("/express-docs/", "Pets")
        self.assertTrue(found.endswith("/swagger-ui-init.js"), found)

    def test_swagger_ui_express_swagger_url(self):
        self.assertTrue(self.assert_finds("/express-url-docs/", "Pets").endswith("/openapi.json"))

    def test_real_page_shapes_name_the_right_spec(self):
        cases = [
            # Swashbuckle's current index.js after its config is rendered
            ('var configObject = {"urls":[{"url":"v1/swagger.json","name":"My API V1"}],"validatorUrl":null};',
             "https://h/swagger/index.js", "https://h/swagger/v1/swagger.json"),
            # drf-spectacular's rendered templates
            ('Redoc.init("/api/schema/", redocSettings, el)', "https://h/api/redoc/", "https://h/api/schema/"),
            ('<redoc spec-url="/api/schema/"></redoc>', "https://h/api/redoc/", "https://h/api/schema/"),
            ('const ui = SwaggerUIBundle({ url: "/api/schema/", dom_id: "#x" })',
             "https://h/api/docs/", "https://h/api/schema/"),
            # Scalar, both ways of configuring it
            ('<script id="api-reference" data-url="/openapi.json"></script>', "https://h/ref", "https://h/openapi.json"),
            ("createApiReference('#app', { url: '/openapi.json' })", "https://h/ref", "https://h/openapi.json"),
        ]
        for body, page, expected in cases:
            self.assertEqual(core.spec_refs_from_body(body, page)[0], expected, body)

    def test_embedded_spec_ignores_what_is_not_strict_json_or_a_spec(self):
        self.assertIsNone(core.embedded_spec("var o = {spec: {paths: getPaths()}}"))
        self.assertIsNone(core.embedded_spec('var o = {"spec": {"replicas": 2}}'))
        self.assertEqual(core.embedded_spec('x = {"spec": {"openapi": "3.0.0", "paths": {}}}')["openapi"], "3.0.0")

    def test_loose_url_scan_stays_on_the_pages_own_origin(self):
        refs = core.spec_refs_from_body('x = "https://other.example/openapi.json"; y = "/mine/swagger.yaml"',
                                        "https://h.example/page")
        self.assertEqual(refs, ["https://h.example/mine/swagger.yaml"])

    def test_springdoc_groups_skip_an_empty_group(self):
        self.assertTrue(self.assert_finds("/grouped/swagger-ui/index.html", "Pets").endswith("/grouped/v3/api-docs/public"))

    def test_a_spec_without_operations_still_loads_when_nothing_better_is_declared(self):
        self.assertTrue(self.assert_finds("/grouped/v3/api-docs/admin", "Empty group").endswith("/admin"))

    def test_swagger_config_primary_group_comes_first(self):
        config = json.dumps({"urls": [{"url": "/a", "name": "a"}, {"url": "/b", "name": "b"}], "urls.primaryName": "b"})
        self.assertEqual(core.spec_refs_from_body(config, "http://h/x"), ["http://h/b", "http://h/a"])

    def test_drf_yasg_page_serves_the_spec_when_asked_for_json(self):
        self.assertTrue(self.assert_finds("/yasg/swagger/", "Legacy").endswith("/yasg/swagger/"))

    def test_drf_spectacular_yaml_sibling_of_docs(self):
        spec, found = fetch_spec(self.api.url + "/api/docs/swagger-ui/")
        self.assertTrue(found.endswith("/api/schema/"))
        # YAML quirks are normalised: int response keys and date values.
        self.assertIn("200", spec["paths"]["/things"]["get"]["responses"])
        self.assertEqual(spec["info"]["version"], "2026-01-01")

    def test_bare_host_root(self):
        self.assert_finds("", "Pets")

    def test_json_object_that_is_not_a_spec_is_rejected(self):
        # Falls through to a real spec instead of accepting {"detail": ...}.
        self.assertTrue(self.assert_finds("/not-a-spec.json", "Pets").endswith("/openapi.json"))

    def test_stock_petstore_initializer_is_ignored(self):
        _, found = fetch_spec(self.api.url + "/petstore-default")
        self.assertNotIn("petstore.swagger.io", found)

    def test_unreachable_host_fails_fast(self):
        import time
        started = time.monotonic()
        with self.assertRaises(core.SpecError):
            fetch_spec("http://127.0.0.1:1/docs", timeout=2)
        self.assertLess(time.monotonic() - started, 3)

    def test_spec_behind_auth(self):
        spec, found = fetch_spec(self.api.url + "/private/openapi.json", auth=Auth(kind="bearer", token="spec-token"))
        self.assertTrue(found.endswith("/private/openapi.json"))
        self.assertEqual(spec["info"]["title"], "Pets")

    def test_locked_down_host_explains_itself(self):
        self.api.server.locked = True
        try:
            with self.assertRaises(core.SpecError) as ctx:
                fetch_spec(self.api.url + "/docs")
        finally:
            self.api.server.locked = False
        self.assertIn("needs authentication", str(ctx.exception))

    def test_credentials_are_not_sent_to_another_origin(self):
        self.api.server.auth_seen.clear()
        _spec, found = fetch_spec(self.api.url + "/foreign-docs", auth=Auth(kind="bearer", token="SECRET"),
                                  headers={"X-Own": "1"})
        self.assertIn("localhost", found)
        self.assertEqual(self.api.server.auth_seen["/foreign-docs"], "Bearer SECRET")
        self.assertIsNone(self.api.server.auth_seen["/foreign-spec.json"])

    def test_candidate_order_prefers_sibling_of_docs(self):
        c = discover_spec_url("http://h/api/docs/swagger-ui/")
        self.assertEqual(c[0], "http://h/api/docs/swagger-ui/")
        self.assertLess(c.index("http://h/api/schema/"), c.index("http://h/api/docs/schema/"))

    def test_normalize_url(self):
        self.assertEqual(normalize_url("localhost:8000/docs"), "http://localhost:8000/docs")
        self.assertEqual(normalize_url("api.example.com"), "https://api.example.com")
        self.assertEqual(normalize_url(" http://x/ "), "http://x/")


class LocalFiles(unittest.TestCase):
    def test_json_and_yaml_files(self):
        with tempfile.TemporaryDirectory() as d:
            j = Path(d) / "spec.json"
            j.write_text(json.dumps(PETS_SPEC), encoding="utf-8")
            y = Path(d) / "spec.yaml"
            y.write_text("openapi: 3.0.0\ninfo: {title: Y, version: '1'}\npaths: {}\n", encoding="utf-8")
            spec, found = fetch_spec(str(j))
            self.assertEqual(spec["info"]["title"], "Pets")
            self.assertTrue(found.startswith("file:"))
            self.assertEqual(server_urls(spec, found), [])  # host unknown
            self.assertEqual(fetch_spec(y.as_uri())[0]["info"]["title"], "Y")

    def test_file_that_is_not_a_spec(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            p.write_text("[1, 2]", encoding="utf-8")
            with self.assertRaises(core.SpecError):
                fetch_spec(str(p))

    def test_alias_bomb_does_not_hang(self):
        bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n"
        prev = "a"
        for i in range(30):
            name = f"l{i}"
            bomb += f"{name}: &{name} [" + ",".join([f"*{prev}"] * 9) + "]\n"
            prev = name
        spec, _ = core.parse_spec_text(bomb + "openapi: 3.0.0\npaths: {}\n")
        self.assertEqual(spec["openapi"], "3.0.0")


class Parsing(unittest.TestCase):
    def setUp(self):
        self.eps = parse_endpoints(PETS_SPEC)
        self.legacy = parse_endpoints(SWAGGER2_SPEC)

    def test_ref_parameter_is_resolved(self):
        ep = find_endpoint(self.eps, "GET", "/pets")
        self.assertEqual({p["name"] for p in ep.parameters}, {"limit", "tags"})

    def test_path_level_parameter_is_inherited(self):
        ep = find_endpoint(self.eps, "GET", "/pets/{id}")
        self.assertEqual(ep.parameters[0]["name"], "id")

    def test_operation_parameter_overrides_path_level(self):
        spec = {"paths": {"/x/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True, "description": "path level"}],
            "get": {"parameters": [{"name": "id", "in": "path", "required": True, "description": "op level"}]},
        }}}
        ep = parse_endpoints(spec)[0]
        self.assertEqual(len(ep.parameters), 1)
        self.assertEqual(ep.parameters[0]["description"], "op level")

    def test_request_body_ref(self):
        ep = find_endpoint(self.eps, "POST", "/pets")
        self.assertTrue(ep.request_body["required"])
        self.assertEqual(ep.request_body["content_type"], "application/json")

    def test_deprecated_flag(self):
        self.assertTrue(find_endpoint(self.eps, "DELETE", "/pets/{id}").deprecated)

    def test_swagger2_body_and_form(self):
        body = find_endpoint(self.legacy, "POST", "/things")
        self.assertEqual(body.request_body["content_type"], "application/json")
        self.assertEqual(body.parameters, [])
        form = find_endpoint(self.legacy, "POST", "/upload")
        self.assertEqual(form.request_body["content_type"], "multipart/form-data")
        self.assertEqual(form.parameters, [])
        self.assertEqual(form.request_body["schema"]["properties"]["doc"]["format"], "binary")

    def test_hostile_shapes_do_not_crash(self):
        for spec in (
            {"paths": None}, {"paths": []}, {"paths": {"/a": None}}, {"paths": {"/a": {"get": "x"}}},
            {"paths": {"/a": {"get": {"parameters": "nope", "tags": 3, "responses": []}}}},
            {"paths": {"/a": {"get": {"parameters": [None, 1, {"$ref": "#/missing"}]}}}},
            {"paths": {"/a": {"$ref": "#/paths/~1a"}}},  # self-referencing path item
        ):
            parse_endpoints(spec)


class HasOperations(unittest.TestCase):
    def test_agrees_with_parse_endpoints(self):
        cases = [
            PETS_SPEC,
            SWAGGER2_SPEC,
            {"openapi": "3.0.0", "paths": {}},
            {"openapi": "3.0.0", "paths": {"/x": {"parameters": [], "summary": "no ops"}}},
            {"openapi": "3.0.0", "paths": {"/x": {"get": "not a dict"}}},
            {"openapi": "3.0.0", "paths": {"/x": {"$ref": "#/components/pathItems/X"}},
             "components": {"pathItems": {"X": {"get": {"responses": {}}}}}},
            {"openapi": "3.0.0", "paths": "broken"},
        ]
        for spec in cases:
            self.assertEqual(core.has_operations(spec), bool(parse_endpoints(spec)), spec)


class Servers(unittest.TestCase):
    def test_relative_server_resolves_against_spec_url(self):
        self.assertEqual(server_urls({"servers": [{"url": "/api"}]}, "https://h/o/spec.json"), ["https://h/api"])
        self.assertEqual(server_urls({"servers": [{"url": "v1"}]}, "https://h/o/spec.json"), ["https://h/o/v1"])

    def test_variables_are_expanded(self):
        spec = {"servers": [{"url": "https://{env}.x.io:{port}/v1",
                             "variables": {"env": {"default": "dev"}, "port": {"default": 8443}}}]}
        self.assertEqual(server_urls(spec, "https://y/"), ["https://dev.x.io:8443/v1"])

    def test_all_servers_are_listed(self):
        spec = {"servers": [{"url": "https://a"}, {"url": "https://b/"}]}
        self.assertEqual(server_urls(spec, "https://y/"), ["https://a", "https://b"])

    def test_swagger2_without_host_keeps_base_path(self):
        self.assertEqual(server_urls(SWAGGER2_SPEC, "http://h:1/swagger.json"), ["http://h:1/legacy"])

    def test_swagger2_scheme_defaults_to_how_spec_was_fetched(self):
        self.assertEqual(server_urls({"host": "h"}, "http://h/s.json"), ["http://h"])
        self.assertEqual(server_urls({"host": "h", "schemes": ["https"]}, "http://h/s.json"), ["https://h"])

    def test_no_servers_uses_spec_origin(self):
        self.assertEqual(server_urls({}, "https://h/a/s.json"), ["https://h"])

    def test_foreign_server_is_detectable(self):
        self.assertTrue(core.origins_differ("https://evil.example", "https://api.example/s.json"))
        self.assertFalse(core.origins_differ("https://api.example/v1", "https://api.example/s.json"))


class Examples(unittest.TestCase):
    def test_read_only_excluded_in_requests_and_write_only_in_responses(self):
        schema = {"type": "object", "properties": {
            "id": {"type": "integer", "readOnly": True},
            "pw": {"type": "string", "writeOnly": True},
        }}
        self.assertEqual(example_from_schema(schema, {}), {"pw": "string"})
        self.assertEqual(example_from_schema(schema, {}, mode="response"), {"id": 0})

    def test_recursive_schema_terminates_quickly(self):
        ex = example_from_schema({"$ref": "#/components/schemas/Owner"}, PETS_SPEC)
        self.assertEqual(ex, {"name": "string", "friend": None})

    def test_allof_with_sibling_properties(self):
        spec = {"A": {"type": "object", "properties": {"a": {"type": "string"}}}}
        schema = {"allOf": [{"$ref": "#/A"}], "properties": {"b": {"type": "integer"}}}
        self.assertEqual(example_from_schema(schema, spec), {"a": "string", "b": 0})

    def test_openapi31_nullable_type_list(self):
        self.assertEqual(example_from_schema({"type": ["string", "null"]}, {}), "string")

    def test_media_type_example_wins(self):
        ep = find_endpoint(parse_endpoints(PETS_SPEC), "POST", "/echo")
        self.assertEqual(example_body(ep, PETS_SPEC), {"a": "from-media-example"})

    def test_openapi31_file_field_gets_the_placeholder(self):
        spec = {"paths": {"/u": {"post": {"requestBody": {"content": {"multipart/form-data": {"schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "contentMediaType": "application/octet-stream"},
                "label": {"type": "string"},
            },
        }}}}}}}}
        ep = parse_endpoints(spec)[0]
        self.assertEqual(example_body(ep, spec), {"file": "@/path/to/file", "label": "string"})

    def test_spec_cannot_plant_a_local_file_upload(self):
        ep = find_endpoint(parse_endpoints(PETS_SPEC), "POST", "/echo")
        form = example_body(ep, PETS_SPEC, "application/x-www-form-urlencoded")
        self.assertEqual(form, {"f": "/etc/passwd"})
        multi = example_body(ep, PETS_SPEC, "multipart/form-data")
        self.assertEqual(multi["note"], "secret.txt")
        self.assertEqual(multi["file"], "@/path/to/file")


class Params(unittest.TestCase):
    def test_path_values_are_percent_encoded(self):
        self.assertEqual(build_url("https://h/", "/a/{id}", {"id": "x/../y z"}), "https://h/a/x%2F..%2Fy%20z")

    def test_split_reports_missing_and_routes_locations(self):
        ep = find_endpoint(parse_endpoints(PETS_SPEC), "GET", "/search/{version}/items")
        parts = split_param_values(ep, {})
        self.assertEqual(sorted(parts.missing), ["q", "version"])
        parts = split_param_values(ep, {("version", "path"): "1", "q": "cat"})
        self.assertEqual((parts.path_params, parts.query, parts.missing), ({"version": "1"}, [("q", "cat")], []))

    def test_undeclared_path_placeholder_is_missing(self):
        ep = parse_endpoints({"paths": {"/a/{ghost}": {"get": {}}}})[0]
        self.assertEqual(split_param_values(ep, {}).missing, ["ghost"])

    def test_array_serialisation(self):
        openapi3 = find_endpoint(parse_endpoints(PETS_SPEC), "GET", "/pets")
        self.assertEqual(split_param_values(openapi3, {"tags": "a, b"}, PETS_SPEC).query, [("tags", "a"), ("tags", "b")])
        legacy = find_endpoint(parse_endpoints(SWAGGER2_SPEC), "GET", "/things/{id}")
        self.assertEqual(split_param_values(legacy, {"id": "1", "ids": "a,b"}).query, [("ids", "a,b")])
        self.assertEqual(split_param_values(legacy, {"id": "1", "multi": "a,b"}).query, [("multi", "a"), ("multi", "b")])

    def test_swagger2_inline_default(self):
        legacy = find_endpoint(parse_endpoints(SWAGGER2_SPEC), "GET", "/things/{id}")
        self.assertEqual(core.default_param_value(legacy.parameters[0]), "7")

    def test_no_guessed_version_value(self):
        self.assertIsNone(core.default_param_value({"name": "version", "in": "path"}))


class AuthAndRequests(ApiTestCase):
    def secure(self, **kwargs):
        return execute_call("GET", self.api.url + "/secure", **kwargs)

    def test_each_auth_kind(self):
        self.assertEqual(self.secure().status, 401)
        self.assertEqual(self.secure(token="good").json["who"], "bearer")
        self.assertEqual(self.secure(auth=Auth(kind="bearer", token="good", prefix="Token")).json["who"], "bearer")
        self.assertEqual(self.secure(auth=Auth(kind="basic", username="ann", password="pw")).json["who"], "basic")
        self.assertEqual(self.secure(auth=Auth(kind="apikey", name="X-Key", token="k1")).json["who"], "apikey")
        self.assertEqual(self.secure(cookies={"sessionid": "abc"}).json["who"], "cookie")

    def test_api_key_in_query_is_hidden_from_displayed_url(self):
        res = self.secure(auth=Auth(kind="apikey", name="key", location="query", token="k1"))
        self.assertEqual(res.json["who"], "apikey")
        self.assertNotIn("k1", res.url)

    def test_explicit_authorization_header_wins(self):
        res = execute_call("GET", self.api.url + "/echo", headers={"authorization": "Custom x"}, token="ignored")
        self.assertEqual(res.json["headers"]["authorization"], "Custom x")

    def echo_body(self, body, content_type):
        res = execute_call("POST", self.api.url + "/echo", body=body, content_type=content_type)
        return res.json["body"], res.json["headers"]["content-type"]

    def test_json_body(self):
        body, ct = self.echo_body({"a": "ü"}, "application/json")
        self.assertEqual(json.loads(body), {"a": "ü"})
        self.assertEqual(ct, "application/json")

    def test_form_body(self):
        body, ct = self.echo_body({"a": "1 2", "b": ["x", "y"]}, "application/x-www-form-urlencoded")
        self.assertEqual(body, "a=1+2&b=x&b=y")
        self.assertIn("x-www-form-urlencoded", ct)

    def test_multipart_with_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "up.txt"
            path.write_text("FILE-CONTENT", encoding="utf-8")
            body, ct = self.echo_body({"doc": f"@{path}", "label": "hi"}, "multipart/form-data")
        self.assertIn("boundary=", ct)
        self.assertIn('filename="up.txt"', body)
        self.assertIn("FILE-CONTENT", body)
        self.assertIn('name="label"', body)

    def test_raw_text_body(self):
        body, ct = self.echo_body("plain", "text/plain")
        self.assertEqual((body, ct), ("plain", "text/plain"))

    def test_missing_upload_is_reported_not_raised(self):
        res = execute_call("POST", self.api.url + "/echo", body={"f": "@/no/such/file"},
                           content_type="multipart/form-data")
        self.assertIn("Could not read upload file", res.error)

    def test_repeated_query_values(self):
        res = execute_call("GET", self.api.url + "/echo", query=[("a", "1"), ("a", "2")])
        self.assertEqual(res.json["query"]["a"], ["1", "2"])

    def test_connection_error_is_returned(self):
        res = execute_call("GET", "http://127.0.0.1:1/x", timeout=2)
        self.assertEqual(res.status, 0)
        self.assertTrue(res.error)

    def test_binary_detection_and_exact_bytes(self):
        res = execute_call("GET", self.api.url + "/binary")
        self.assertTrue(res.is_binary)
        self.assertEqual(res.content, b"\x89PNG\x00\x01\x02")
        self.assertEqual(res.size, 7)

    def test_no_charset_decodes_as_utf8_without_guessing(self):
        # requests' charset guessing tries many codecs and took seconds per binary body.
        from unittest import mock
        import requests
        guess = mock.PropertyMock(side_effect=AssertionError("charset guessed"))
        with mock.patch.object(requests.Response, "apparent_encoding", guess):
            self.assertEqual(execute_call("GET", self.api.url + "/no-charset").text, "café ✓")
            self.assertTrue(execute_call("GET", self.api.url + "/binary").is_binary)
            spec, _ = fetch_spec(self.api.url + "/api/schema/")
        self.assertTrue(spec["paths"])

    def test_json_is_not_binary(self):
        self.assertFalse(execute_call("GET", self.api.url + "/pets").is_binary)


class Curl(unittest.TestCase):
    def test_json_and_quoting(self):
        cmd = to_curl("post", "http://h/a", body={"q": "it's"}, query=[("x", "1 2")], token="t", verify=False)
        self.assertIn("curl -X POST -k", cmd)
        self.assertIn("http://h/a?x=1+2", cmd)
        self.assertIn("Authorization: Bearer t", cmd)
        self.assertIn("Content-Type: application/json", cmd)
        self.assertIn("--data-raw", cmd)

    def test_multipart_does_not_read_the_file(self):
        cmd = to_curl("POST", "http://h/a", body={"f": "@/no/such", "n": "1"}, content_type="multipart/form-data")
        self.assertIn("-F f=@/no/such", cmd)
        self.assertIn("--form-string n=1", cmd)


class Validation(ApiTestCase):
    def call(self, path):
        ep = find_endpoint(parse_endpoints(PETS_SPEC), "GET", path)
        return validate_response(ep, execute_call("GET", self.api.url + path), PETS_SPEC)

    def test_matching_response(self):
        self.assertEqual(self.call("/pets"), [])

    def test_schema_mismatch_is_reported_with_location(self):
        issues = self.call("/broken")
        self.assertTrue(any("$.id" in i and "integer" in i for i in issues), issues)
        self.assertTrue(any("missing required property 'name'" in i for i in issues), issues)
        self.assertTrue(any("$.status" in i for i in issues), issues)

    def test_undocumented_status(self):
        self.assertIn("isn't documented", self.call("/undocumented")[0])

    def test_keywords(self):
        cases = [
            (1, {"type": "string"}, 1),
            (True, {"type": "integer"}, 1),
            (1.0, {"type": "integer"}, 0),
            (None, {"type": "string", "nullable": True}, 0),
            (None, {"type": ["string", "null"]}, 0),
            ("a", {"enum": ["b"]}, 1),
            ("a", {"minLength": 2}, 1),
            ("abc", {"pattern": "^a"}, 0),
            ("abc", {"pattern": "("}, 0),  # uncompilable pattern must not misreport or raise
            (5, {"minimum": 6}, 1),
            (5, {"exclusiveMaximum": 5}, 1),
            ([1], {"type": "array", "items": {"type": "string"}}, 1),
            ([], {"minItems": 1}, 1),
            ({"a": 1}, {"additionalProperties": False}, 1),
            ({"a": 1}, {"additionalProperties": {"type": "string"}}, 1),
            (1, {"anyOf": [{"type": "string"}, {"type": "integer"}]}, 0),
            (1, {"oneOf": [{"type": "integer"}, {"minimum": 0}]}, 1),
            ({"a": 1}, {"allOf": [{"required": ["a"]}, {"required": ["b"]}]}, 1),
        ]
        for value, schema, expected in cases:
            self.assertEqual(len(validate_schema(value, schema, {})), expected, (value, schema))

    def test_self_referencing_ref_terminates(self):
        spec = {"A": {"$ref": "#/A"}}
        self.assertEqual(validate_schema(1, {"$ref": "#/A"}, spec), [])

    def test_write_only_required_is_not_expected_in_responses(self):
        schema = {"type": "object", "required": ["pw"], "properties": {"pw": {"type": "string", "writeOnly": True}}}
        self.assertEqual(validate_schema({}, schema, {}), [])


class Tokens(unittest.TestCase):
    def test_common_shapes(self):
        cases = {
            "t1": {"token": "t1"},
            "t2": {"access": "t2", "refresh": "r"},
            "t3": {"data": {"accessToken": "t3"}},
            "t4": {"access_token": "t4", "token_type": "bearer"},
            "t5": {"result": {"auth": {"jwt": "t5"}}},
            "t6": {"key": "t6"},
            "t7": {"Token": "t7"},
        }
        for expected, body in cases.items():
            self.assertEqual(extract_token(body), expected)

    def test_refresh_token_alone_is_not_used(self):
        self.assertIsNone(extract_token({"refresh": {"token": "r"}}))
        self.assertIsNone(extract_token({"refresh_token": "r"}))

    def test_dotted_path(self):
        self.assertEqual(extract_token({"a": {"b": [{"c": "x"}]}}, "a.b.0.c"), "x")
        self.assertIsNone(extract_token({"token": "x"}, "not.there"))


class Login(ApiTestCase):
    def test_json_login(self):
        r = login(self.api.url, "a@b", "pw", auth_path="/login", username_field="email",
                  extra_fields={"device_id": "d"})
        self.assertEqual(r.token, "a-token")

    def test_path_without_leading_slash_and_absolute_url(self):
        for path in ("login", self.api.url + "/login"):
            r = login(self.api.url + "/some/page", "a", "pw", auth_path=path, username_field="email",
                      extra_fields={"device_id": "d"})
            self.assertEqual(r.token, "a-token", path)

    def test_form_login(self):
        self.assertEqual(login(self.api.url, "a", "pw", auth_path="/oauth/token", form=True).token, "oauth-token")
        self.assertEqual(login(self.api.url, "a", "pw", auth_path="/oauth/token").status, 415)

    def test_wrapped_token_skips_refresh(self):
        self.assertEqual(login(self.api.url, "a", "b", auth_path="/wrapped-login").token, "deep-token")

    def test_token_path(self):
        r = login(self.api.url, "a", "b", auth_path="/custom-login", token_path="payload.weird_name")
        self.assertEqual(r.token, "custom-token")

    def test_token_in_response_header(self):
        self.assertEqual(login(self.api.url, "a", "b", auth_path="/header-login").token, "header-token")

    def test_cookie_session(self):
        r = login(self.api.url, "a", "b", auth_path="/cookie-login")
        self.assertTrue(r.ok)
        self.assertIsNone(r.token)
        self.assertEqual(r.cookies, {"sessionid": "abc"})

    def test_no_token_is_not_ok(self):
        r = login(self.api.url, "a", "b", auth_path="/no-token-login")
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 200)

    def test_bad_credentials(self):
        r = login(self.api.url, "a", "x", auth_path="/login", username_field="email", extra_fields={"device_id": "d"})
        self.assertFalse(r.ok)
        self.assertEqual(r.status, 401)


class LoginHelpers(unittest.TestCase):
    def test_candidates_exclude_refresh_and_rank_login_first(self):
        eps = parse_endpoints(PETS_SPEC)
        self.assertEqual(find_login_candidates(eps, PETS_SPEC), ["/login"])

    def test_oauth2_token_url_comes_first(self):
        spec = {
            "paths": {"/auth/login": {"post": {}}},
            "components": {"securitySchemes": {"o": {
                "type": "oauth2", "flows": {"password": {"tokenUrl": "/oauth/token", "scopes": {}}},
            }}},
        }
        self.assertEqual(find_login_candidates(parse_endpoints(spec), spec), ["/oauth/token", "/auth/login"])

    def test_shape_from_schema(self):
        ep = find_endpoint(parse_endpoints(PETS_SPEC), "POST", "/login")
        shape = guess_login_shape(ep, PETS_SPEC)
        self.assertEqual((shape.username_field, shape.password_field, shape.form), ("email", "password", False))
        self.assertEqual(shape.extra_required, ["device_id"])

    def test_field_error_shapes(self):
        self.assertEqual(extract_field_errors({"errors": {"Email": ["x"]}, "title": "t"}), {"Email": ["x"]})
        self.assertEqual(extract_field_errors({"device_id": ["x"], "detail": "no"}), {"device_id": ["x"]})
        fastapi = {"detail": [{"loc": ["body", "email"], "msg": "field required"}]}
        self.assertEqual(extract_field_errors(fastapi), {"email": "field required"})
        self.assertEqual(extract_field_errors({"detail": "bad credentials"}), {})
        self.assertEqual(extract_field_errors("nope"), {})


class Security(unittest.TestCase):
    def test_scheme_normalisation(self):
        kinds = {s.key: s for s in parse_security_schemes(SWAGGER2_SPEC)}
        self.assertEqual(kinds["apiKey"].kind, "apikey")
        self.assertEqual(kinds["apiKey"].name, "X-Key")
        self.assertEqual(kinds["jwt"].kind, "bearer")
        self.assertEqual(parse_security_schemes(PETS_SPEC)[0].kind, "bearer")

    def test_url_redaction(self):
        out = redact_url("https://u:hunter2@h/p?api_key=abc&page=2&token=t")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("abc", out)
        self.assertNotIn("=t", out)
        self.assertIn("page=2", out)

    def test_failures_hide_query_secrets_in_logs_and_results(self):
        for kwargs in (
            {"query": {"api_key": "SECRET"}},
            {"auth": Auth(kind="apikey", name="custom", location="query", token="SECRET")},
        ):
            with self.assertLogs("specprobe", level="DEBUG") as logs:
                res = execute_call("GET", "http://127.0.0.1:1/x", timeout=1, **kwargs)
            self.assertTrue(res.error)
            self.assertNotIn("SECRET", "\n".join(logs.output))
            self.assertNotIn("SECRET", res.error)
            if "auth" in kwargs:
                # The tool added this key itself, so it must not show in the displayed URL.
                self.assertNotIn("SECRET", res.url)

    def test_spec_load_failure_hides_query_secrets(self):
        with self.assertRaises(core.SpecError) as ctx:
            fetch_spec("http://127.0.0.1:1/openapi.json?api_key=SECRET", timeout=1)
        self.assertNotIn("SECRET", str(ctx.exception))


class Audit(unittest.TestCase):
    def test_plan_uses_declared_values_and_skips_the_rest(self):
        eps = parse_endpoints(PETS_SPEC)
        targets, skipped = plan_audit(eps, PETS_SPEC)
        planned = {ep.path for ep, _ in targets}
        missing = {s["path"]: s["missing"] for s in skipped}
        self.assertIn("/pets", planned)
        self.assertEqual(missing["/pets/{id}"], ["id"])
        self.assertEqual(missing["/search/{version}/items"], ["q"])

    def test_params_fill_gaps(self):
        eps = parse_endpoints(PETS_SPEC)
        targets, _ = plan_audit(eps, PETS_SPEC, params={"id": "1", "q": "x"})
        planned = {ep.path: parts for ep, parts in targets}
        self.assertEqual(planned["/pets/{id}"].path_params, {"id": "1"})
        self.assertEqual(planned["/search/{version}/items"].path_params, {"version": "2"})

    def test_only_get_is_ever_planned(self):
        targets, _ = plan_audit(parse_endpoints(PETS_SPEC), PETS_SPEC, params={"id": "1", "q": "x"})
        self.assertEqual({ep.method for ep, _ in targets}, {"GET"})


class SharedSession(ApiTestCase):
    def test_calls_reuse_one_connection(self):
        before = len(self.api.server.peers)
        with requests.Session() as session:
            for _ in range(3):
                res = execute_call("GET", self.api.url + "/pets", session=session)
                self.assertEqual(res.status, 200)
        self.assertEqual(len(set(self.api.server.peers[before:])), 1)

    def test_cookies_never_carry_to_the_next_call(self):
        with requests.Session() as session:
            execute_call("GET", self.api.url + "/give-cookie", session=session)
            res = execute_call("GET", self.api.url + "/echo", session=session)
        self.assertNotIn("cookie", res.json["headers"])

    def test_explicit_cookies_still_sent(self):
        with requests.Session() as session:
            res = execute_call("GET", self.api.url + "/echo", cookies={"a": "1"}, session=session)
        self.assertEqual(res.json["headers"].get("cookie"), "a=1")

    def test_audit_one_uses_the_session(self):
        eps = parse_endpoints(PETS_SPEC)
        targets, _ = plan_audit(eps, PETS_SPEC)
        before = len(self.api.server.peers)
        with requests.Session() as session:
            rows = [audit_one(ep, parts, self.api.url, session=session) for ep, parts in targets]
        self.assertTrue(rows)
        self.assertEqual(len(set(self.api.server.peers[before:])), 1)


class RunAudit(ApiTestCase):
    def setUp(self):
        self.targets, _ = plan_audit(parse_endpoints(PETS_SPEC), PETS_SPEC, params={"id": "1", "q": "x"})
        self.slow = [t for t in self.targets if t[0].path == "/slow"]

    def test_parallel_gives_the_same_rows_in_plan_order(self):
        sequential = [(r.path, r.status) for r in run_audit(self.targets, self.api.url)]
        parallel = [(r.path, r.status) for r in run_audit(self.targets, self.api.url, jobs=4)]
        self.assertEqual(sequential, parallel)
        self.assertEqual([p for p, _ in parallel], [ep.path for ep, _ in self.targets])

    def test_parallel_overlaps_requests(self):
        started = time.perf_counter()
        rows = list(run_audit(self.slow * 3, self.api.url, jobs=3))
        self.assertEqual([r.status for r in rows], [200, 200, 200])
        self.assertLess(time.perf_counter() - started, 3.0)  # one at a time takes 4.5 s

    def test_closing_early_cancels_calls_not_started(self):
        before = self.api.server.seen.count("/slow")
        rows = run_audit(self.slow * 6, self.api.url, jobs=2)
        next(rows)
        rows.close()
        # By the first result, both threads may have moved on to the next pair.
        # The last two are still queued, and those never reach the server.
        self.assertLessEqual(self.api.server.seen.count("/slow") - before, 4)


class NoBackendAssumptions(unittest.TestCase):
    def test_sources_name_no_specific_backend(self):
        root = Path(core.__file__).parent
        for path in root.glob("*.py"):
            text = path.read_text(encoding="utf-8").lower()
            for word in ("customerinfo", "device_id\"", "/api/identity", "localhost:8000"):
                self.assertNotIn(word, text, path.name)


if __name__ == "__main__":
    unittest.main()
