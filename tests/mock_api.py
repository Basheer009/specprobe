"""A local HTTP server for the tests.

It imitates how real frameworks publish their specs and docs pages, and it serves
endpoints covering the auth styles and body types the tool has to handle. It uses
only the standard library and binds to a random loopback port.
"""

from __future__ import annotations

import base64
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PETS_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Pets", "version": "1.2"},
    "paths": {
        "/pets": {
            "get": {
                "tags": ["pets"],
                "summary": "List pets",
                "operationId": "listPets",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 10}},
                    {"$ref": "#/components/parameters/Tags"},
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {"application/json": {"schema": {
                            "type": "array", "items": {"$ref": "#/components/schemas/Pet"},
                        }}},
                    }
                },
            },
            "post": {
                "tags": ["pets"],
                "requestBody": {"$ref": "#/components/requestBodies/NewPet"},
                "responses": {"201": {"description": "created"}},
            },
        },
        "/pets/{id}": {
            "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": {
                "tags": ["pets"],
                "responses": {"200": {"description": "ok", "content": {"application/json": {
                    "schema": {"$ref": "#/components/schemas/Pet"}}}}},
            },
            "delete": {"tags": ["pets"], "deprecated": True, "responses": {"204": {"description": "gone"}}},
        },
        "/secure": {"get": {
            "tags": ["auth"], "security": [{"bearerAuth": []}],
            "responses": {"200": {"description": "ok"}, "401": {"description": "denied"}},
        }},
        "/broken": {"get": {
            "tags": ["contract"],
            "responses": {"200": {"description": "ok", "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Pet"}}}}},
        }},
        "/undocumented": {"get": {"tags": ["contract"], "responses": {"200": {"description": "ok"}}}},
        "/boom": {"get": {"tags": ["contract"], "responses": {"500": {"description": "fails"}}}},
        "/search/{version}/items": {"get": {
            "tags": ["params"],
            "parameters": [
                {"name": "version", "in": "path", "required": True, "schema": {"type": "string", "default": "2"}},
                {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}},
            ],
            "responses": {"200": {"description": "ok"}},
        }},
        "/echo": {
            "post": {
                "tags": ["echo"],
                "requestBody": {"content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"a": {"type": "string"}}},
                        "example": {"a": "from-media-example"},
                    },
                    "application/x-www-form-urlencoded": {"schema": {
                        "type": "object", "properties": {"f": {"type": "string", "example": "@/etc/passwd"}},
                    }},
                    "multipart/form-data": {"schema": {
                        "type": "object",
                        "properties": {
                            "file": {"type": "string", "format": "binary"},
                            "note": {"type": "string", "example": "@secret.txt"},
                        },
                    }},
                    "text/plain": {"schema": {"type": "string"}},
                }},
                "responses": {"200": {"description": "ok"}},
            },
            "get": {
                "tags": ["echo"],
                "parameters": [
                    {"name": "X-Trace", "in": "header", "schema": {"type": "string"}},
                    {"name": "sid", "in": "cookie", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            },
        },
        "/binary": {"get": {"tags": ["echo"], "responses": {"200": {"description": "ok"}}}},
        "/slow": {"get": {"tags": ["echo"], "responses": {"200": {"description": "ok"}}}},
        "/login": {"post": {
            "tags": ["auth"],
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object",
                "required": ["email", "password", "device_id"],
                "properties": {
                    "email": {"type": "string"},
                    "password": {"type": "string"},
                    "device_id": {"type": "string"},
                },
            }}}},
            "responses": {"200": {"description": "ok"}},
        }},
        "/login/refresh": {"post": {"tags": ["auth"], "responses": {"200": {"description": "ok"}}}},
    },
    "components": {
        "parameters": {
            "Tags": {
                "name": "tags", "in": "query",
                "schema": {"type": "array", "items": {"type": "string"}},
            }
        },
        "requestBodies": {
            "NewPet": {
                "required": True,
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}},
            }
        },
        "schemas": {
            "Pet": {
                "type": "object",
                "required": ["id", "name"],
                "properties": {
                    "id": {"type": "integer", "readOnly": True},
                    "name": {"type": "string"},
                    "owner": {"$ref": "#/components/schemas/Owner"},
                    "status": {"type": "string", "enum": ["available", "sold"]},
                    "born": {"type": "string", "format": "date"},
                },
            },
            "Owner": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "friend": {"$ref": "#/components/schemas/Owner"},
                },
            },
        },
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
    },
}

SWAGGER2_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Legacy", "version": "0.9"},
    "basePath": "/legacy",
    "consumes": ["application/json"],
    "securityDefinitions": {
        "apiKey": {"type": "apiKey", "name": "X-Key", "in": "header"},
        "jwt": {"type": "apiKey", "name": "Authorization", "in": "header"},
    },
    "paths": {
        "/things/{id}": {"get": {
            "tags": ["things"],
            "parameters": [
                {"name": "id", "in": "path", "required": True, "type": "integer", "default": 7},
                {"name": "ids", "in": "query", "type": "array", "items": {"type": "string"}},
                {"name": "multi", "in": "query", "type": "array", "items": {"type": "string"},
                 "collectionFormat": "multi"},
            ],
            "responses": {200: {"description": "ok", "schema": {"type": "object"}}},
        }},
        "/things": {"post": {
            "tags": ["things"],
            "parameters": [{"name": "body", "in": "body", "required": True,
                            "schema": {"$ref": "#/definitions/Thing"}}],
            "responses": {"201": {"description": "created"}},
        }},
        "/upload": {"post": {
            "tags": ["things"],
            "consumes": ["multipart/form-data"],
            "parameters": [
                {"name": "doc", "in": "formData", "type": "file", "required": True},
                {"name": "label", "in": "formData", "type": "string"},
            ],
            "responses": {"200": {"description": "ok"}},
        }},
    },
    "definitions": {"Thing": {"type": "object", "properties": {"title": {"type": "string"}}}},
}

_YAML_SPEC = """\
openapi: 3.1.0
info:
  title: Yaml API
  version: 2026-01-01
paths:
  /things:
    get:
      responses:
        200:
          description: ok
"""


def _page(*scripts: str, body: str = "") -> bytes:
    tags = "".join(f'<script src="{s}"></script>' for s in scripts)
    return f"<!doctype html><html><head>{tags}</head><body>{body}</body></html>".encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status=200, body=b"", ctype="application/json", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _echo(self, raw: bytes = b""):
        parts = urlsplit(self.path)
        self.server.seen.append(self.path)
        self._send(body={
            "path": parts.path,
            "query": parse_qs(parts.query),
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": raw.decode("utf-8", "replace"),
        })

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        self.server.seen.append(self.path)
        self.server.auth_seen[path] = self.headers.get("Authorization")

        if self.server.locked:
            return self._send(401, {"detail": "login required"})

        # Spec publishing conventions
        if path == "/hosted-ui/":  # the Swagger project's own hosted pages
            return self._send(body=_page("./swagger-ui-bundle.js", "./swagger-initializer.js"), ctype="text/html")
        if path == "/hosted-ui/swagger-initializer.js":
            host = self.headers.get("Host")
            return self._send(
                body=(
                    'const defaultDefinitionUrl = "https://petstore.swagger.io/v2/swagger.json";\n'
                    f"const ossServices = `other.example=https://other.example/openapi.json,"
                    f"{host}=http://{host}/hosted-ui/api/v3/openapi.json`;\n"
                    "window.ui = SwaggerUIBundle({ url: definitionURL, \"dom_id\": \"#swagger-ui\" })"
                ),
                ctype="application/javascript",
            )
        if path == "/hosted-ui/api/v3/openapi.json":
            return self._send(body=PETS_SPEC)
        if path == "/express-docs/":  # swagger-ui-express with a spec object
            return self._send(body=_page("./swagger-ui-init.js"), ctype="text/html")
        if path == "/express-docs/swagger-ui-init.js":
            options = json.dumps({"customOptions": {}, "swaggerDoc": PETS_SPEC}, indent=2)
            return self._send(body=f"window.onload = function() {{\n  var options = {options};\n"
                                   "  url = options.swaggerUrl || url\n}",
                              ctype="application/javascript")
        if path == "/express-url-docs/swagger-ui-init.js":  # swagger-ui-express with swaggerUrl
            return self._send(body='var options = {"customOptions": {}, "swaggerUrl": "/openapi.json"};',
                              ctype="application/javascript")
        if path == "/express-url-docs/":
            return self._send(body=_page("./swagger-ui-init.js"), ctype="text/html")
        if path == "/foreign-docs":  # names a spec on a different origin
            port = self.server.server_address[1]
            return self._send(body=f"<script>SwaggerUIBundle({{url: 'http://localhost:{port}/foreign-spec.json'}})</script>",
                              ctype="text/html")
        if path == "/foreign-spec.json":
            return self._send(body=PETS_SPEC)
        if path == "/openapi.json":
            return self._send(body=PETS_SPEC)
        if path == "/docs":  # FastAPI style
            return self._send(body=_page(body="<script>SwaggerUIBundle({url: '/openapi.json', dom_id: '#ui'})</script>"),
                              ctype="text/html")
        if path == "/redoc":
            return self._send(body=_page(body='<redoc spec-url="/openapi.json"></redoc>'), ctype="text/html")
        if path == "/grouped/swagger-ui/index.html":  # springdoc with group-configs
            return self._send(body=_page("/grouped/swagger-ui/swagger-initializer.js"), ctype="text/html")
        if path == "/grouped/swagger-ui/swagger-initializer.js":
            return self._send(body='window.ui = SwaggerUIBundle({url: "https://petstore.swagger.io/v2/swagger.json",'
                                   ' "configUrl" : "/grouped/v3/api-docs/swagger-config"})',
                              ctype="text/javascript")
        if path == "/grouped/v3/api-docs/swagger-config":
            # The first group listed matches no endpoints.
            return self._send(body={"configUrl": "/grouped/v3/api-docs/swagger-config", "urls": [
                {"url": "/grouped/v3/api-docs/admin", "name": "admin"},
                {"url": "/grouped/v3/api-docs/public", "name": "public"},
            ]})
        if path == "/grouped/v3/api-docs/admin":
            return self._send(body={"openapi": "3.1.0", "info": {"title": "Empty group", "version": "v1"}, "paths": {}})
        if path == "/grouped/v3/api-docs/public":
            return self._send(body=PETS_SPEC)
        if path == "/yasg/swagger/":
            # drf-yasg: the UI page names no spec URL; it serves the spec itself to
            # clients that ask for JSON or YAML (its JS adds ?format=openapi).
            accept = self.headers.get("Accept", "")
            if "format=openapi" in parts.query or accept.split(",")[0].strip() in ("application/json", "application/yaml"):
                return self._send(body=SWAGGER2_SPEC, ctype="application/openapi+json")
            return self._send(body=_page("/static/drf-yasg/swagger-ui-init.js"), ctype="text/html")
        if path == "/api/docs/swagger-ui/":  # drf-spectacular, with the URL hidden from us
            return self._send(body=_page(body="<div id='ui'></div>"), ctype="text/html")
        if path == "/api/schema/":
            return self._send(body=_YAML_SPEC, ctype="application/yaml")
        if path == "/swagger/index.html":  # Swashbuckle
            return self._send(body=_page("index.js", "swagger-ui-bundle.js"), ctype="text/html")
        if path == "/swagger/index.js":
            return self._send(body='var configObject = JSON.parse(\'{"urls":[{"url":"v1\\/swagger.json","name":"V1"}]}\');',
                              ctype="application/javascript")
        if path == "/swagger/v1/swagger.json":
            return self._send(body=SWAGGER2_SPEC)
        if path == "/swagger-ui/index.html":  # springdoc
            return self._send(body=_page("/swagger-ui/swagger-initializer.js"), ctype="text/html")
        if path == "/swagger-ui/swagger-initializer.js":
            return self._send(body='window.ui = SwaggerUIBundle({configUrl: "/v3/api-docs/swagger-config"})',
                              ctype="application/javascript")
        if path == "/v3/api-docs/swagger-config":
            return self._send(body={"configUrl": "/v3/api-docs/swagger-config", "url": "/v3/api-docs"})
        if path == "/v3/api-docs":
            return self._send(body=PETS_SPEC)
        if path == "/custom/spec-location":
            return self._send(body=PETS_SPEC)
        if path == "/petstore-default":  # stock Swagger UI, never configured
            return self._send(body="<script>SwaggerUIBundle({url: 'https://petstore.swagger.io/v2/swagger.json'})</script>",
                              ctype="text/html")
        if path == "/not-a-spec.json":
            return self._send(body={"detail": "hello"})
        if path == "/private/openapi.json":
            if self.headers.get("Authorization") != "Bearer spec-token":
                return self._send(401, {"detail": "no"})
            return self._send(body=PETS_SPEC)

        # API endpoints
        if path == "/secure":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer good" or auth == "Token good":
                return self._send(body={"who": "bearer"})
            if auth == "Basic " + base64.b64encode(b"ann:pw").decode():
                return self._send(body={"who": "basic"})
            if self.headers.get("X-Key") == "k1" or parse_qs(parts.query).get("key") == ["k1"]:
                return self._send(body={"who": "apikey"})
            if "sessionid=abc" in self.headers.get("Cookie", ""):
                return self._send(body={"who": "cookie"})
            return self._send(401, {"detail": "denied"}, headers={"WWW-Authenticate": "Bearer"})
        if path == "/pets":
            return self._send(body=[{"id": 1, "name": "Rex", "status": "available"}])
        if path.startswith("/pets/"):
            return self._send(body={"id": 1, "name": "Rex"})
        if path == "/broken":
            return self._send(body={"id": "not-a-number", "status": "lost"})
        if path == "/undocumented":
            return self._send(418, {"detail": "teapot"})
        if path == "/boom":
            return self._send(500, {"detail": "boom"})
        if path.startswith("/search/"):
            return self._send(body={"ok": True})
        if path == "/no-charset":
            return self._send(body="café ✓".encode("utf-8"), ctype="application/x-custom")
        if path == "/binary":
            return self._send(body=b"\x89PNG\x00\x01\x02", ctype="image/png")
        if path == "/slow":
            time.sleep(1.5)
            return self._send(body={"slow": True})
        if path == "/echo" or path.startswith("/legacy/things"):
            return self._echo()
        return self._send(404, {"detail": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        raw = self._body()
        ctype = self.headers.get("Content-Type", "")
        if path == "/login":
            data = json.loads(raw or b"{}")
            if "email" not in data:
                return self._send(400, {"email": ["required"], "device_id": ["required"]})
            if "device_id" not in data:
                return self._send(400, {"device_id": ["required"]})
            if data.get("password") != "pw":
                return self._send(401, {"detail": "bad credentials"})
            return self._send(body={"refresh": "r-token", "access": "a-token"})
        if path == "/oauth/token":
            if "x-www-form-urlencoded" not in ctype:
                return self._send(415, {"detail": "form required"})
            data = parse_qs(raw.decode())
            if data.get("password") != ["pw"]:
                return self._send(401, {"error": "invalid_grant"})
            return self._send(body={"access_token": "oauth-token", "token_type": "bearer"})
        if path == "/wrapped-login":
            return self._send(body={"result": {"session": {"refresh": "no", "jwt": "deep-token"}}})
        if path == "/custom-login":
            return self._send(body={"payload": {"weird_name": "custom-token"}})
        if path == "/header-login":
            return self._send(body={"ok": True}, headers={"Authorization": "Bearer header-token"})
        if path == "/cookie-login":
            return self._send(body={"ok": True}, headers={"Set-Cookie": "sessionid=abc; Path=/"})
        if path == "/no-token-login":
            return self._send(body={"welcome": True})
        return self._echo(raw)

    do_PUT = do_POST
    do_PATCH = do_POST

    def do_DELETE(self):
        self._send(204)


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Tests abandon requests on purpose, so a client hanging up isn't a failure.
        if not isinstance(sys.exc_info()[1], ConnectionError):
            super().handle_error(request, client_address)


class MockApi:
    def __enter__(self) -> "MockApi":
        self.server = QuietServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.seen = []
        self.server.auth_seen = {}
        self.server.locked = False
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
