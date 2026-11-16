"""Shared logic for Swagger/OpenAPI loading, request execution and checking.

Used by both the PySide6 GUI (gui.py) and the CLI (cli.py). Nothing in this
module knows about a specific backend: every convention it relies on comes from
the OpenAPI/Swagger specs themselves or from widely used framework defaults.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import os
import re
import shlex
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Union
from urllib.parse import (
    parse_qsl,
    quote,
    quote_plus,
    unquote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests
import urllib3
import yaml

# Skipping TLS verification is an explicit user choice here (--no-verify or the
# GUI checkbox), so urllib3's per-request warning would only add noise.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("specprobe")
log.addHandler(logging.NullHandler())

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}

_SECRET_NAME = re.compile(r"token|key|secret|passw|pwd|auth|signature|sig$|credential", re.I)


class SpecError(RuntimeError):
    """The spec could not be located, fetched or parsed."""


def redact_url(url: str) -> str:
    """Hide credential-looking query values and URL passwords, for log output."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc
    if parts.password:
        netloc = netloc.replace(f":{parts.password}@", ":***@")
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode([(k, "***" if _SECRET_NAME.search(k) else v) for k, v in pairs], safe="*")
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def _default_utf8(r: requests.Response) -> requests.Response:
    """Decode a response with no declared charset as UTF-8.

    Otherwise requests guesses the charset by trying many codecs over the whole
    body, which takes seconds on large or binary bodies.
    """
    if not r.encoding:
        r.encoding = "utf-8"
    return r


def scrub_error(message: Any, url: str, secret: str = "") -> str:
    """Remove a URL's secrets from error text.

    requests puts the full request URL in its exception messages, so an API key
    sent in the query would otherwise reach logs and error displays. `secret` is a
    value known to be sensitive whatever its parameter is called.
    """
    text = str(message)
    if secret:
        text = text.replace(quote_plus(secret), "***").replace(secret, "***")
    try:
        parts = urlsplit(url)
    except ValueError:
        return text
    if parts.query:
        text = text.replace(parts.query, urlsplit(redact_url(url)).query)
    if parts.password:
        text = text.replace(parts.password, "***")
    return text


# ---------------------------------------------------------------------------
# Spec discovery and loading
# ---------------------------------------------------------------------------

# Default spec locations of the common OpenAPI generators, tried relative to the
# URL the user gave and to each of its ancestors.
WELL_KNOWN_SPEC_PATHS = (
    "openapi.json",             # FastAPI and many others
    "openapi.yaml",
    "openapi.yml",
    "swagger.json",             # drf-yasg, generic
    "swagger.yaml",
    "swagger.yml",
    "v1/swagger.json",          # Swashbuckle, relative to /swagger/
    "swagger/v1/swagger.json",  # Swashbuckle
    "swagger/swagger.json",
    "swagger/doc.json",         # swaggo (Go)
    "doc.json",
    "v3/api-docs",              # springdoc
    "v2/api-docs",              # springfox
    "api-docs",
    "api-docs.json",            # l5-swagger (Laravel)
    "api-docs-json",            # NestJS
    "api-json",                 # NestJS default
    "schema/",                  # drf-spectacular
    "schema",
    "schema.json",
    "schema.yaml",
    "schema.yml",
)

_DOCS_UI_SEGMENTS = {"docs", "doc", "swagger", "swagger-ui", "redoc", "ui", "api-docs", "index.html"}
_MAX_SPEC_REQUESTS = 80


def normalize_url(raw: str) -> str:
    """Add a scheme to a bare host. Loopback hosts get http, the rest https."""
    u = (raw or "").strip()
    if not u:
        raise SpecError("No URL given.")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        return u
    host = u.split("/", 1)[0].split(":", 1)[0].lower()
    local = host in ("localhost", "127.0.0.1", "0.0.0.0") or host.startswith(("192.168.", "10."))
    return ("http://" if local else "https://") + u


def is_local_source(source: str) -> bool:
    """True when `source` names a spec file on disk rather than a URL."""
    s = (source or "").strip()
    if s.lower().startswith("file://"):
        return True
    if "://" in s:
        return False
    try:
        return os.path.isfile(s)
    except (OSError, ValueError):
        return False


def _local_path(source: str) -> Path:
    s = source.strip()
    if s.lower().startswith("file://"):
        p = unquote(urlsplit(s).path)
        # file:///C:/x.json -> /C:/x.json on Windows
        if re.match(r"^/[A-Za-z]:", p):
            p = p[1:]
        return Path(p)
    return Path(s)


def discover_spec_url(base_url: str) -> list[str]:
    """Ordered guesses for where the spec lives, given any URL near it.

    The exact URL always comes first, because it may be the spec or a docs page
    that names the spec. After that come the conventional locations, walking from
    the given path up to the host root. When the URL contains a docs segment, its
    parent is tried first: `/api/docs/swagger-ui/` usually pairs with
    `/api/schema/`, a sibling of `docs` rather than something nested beneath it.
    """
    u = normalize_url(base_url)
    parts = urlsplit(u)
    root = f"{parts.scheme}://{parts.netloc}"
    segments = [s for s in parts.path.split("/") if s]

    prefixes: list[list[str]] = []
    lowered = [s.lower() for s in segments]
    for i, seg in enumerate(lowered):
        if seg in ("docs", "doc", "swagger-ui", "redoc"):
            prefixes.append(segments[:i])
            break
    for i in range(len(segments), -1, -1):
        prefixes.append(segments[:i])

    out: list[str] = [u]
    # drf-yasg serves the spec from the docs page itself with ?format=openapi.
    if not parts.query and lowered and lowered[-1] in _DOCS_UI_SEGMENTS:
        out.append(u + "?format=openapi")
    for prefix in prefixes:
        base = root + ("/" + "/".join(prefix) if prefix else "")
        for name in WELL_KNOWN_SPEC_PATHS:
            out.append(f"{base}/{name}")
    return list(dict.fromkeys(out))


def _plain_data(node: Any, memo: Optional[dict] = None) -> Any:
    """Make YAML output JSON-like: string keys and ISO dates.

    YAML reads `200:` as an int key and `2024-01-01` as a date. The memo keeps
    aliases shared, so an alias-bomb document cannot expand exponentially here.
    """
    memo = {} if memo is None else memo
    if isinstance(node, (dict, list)):
        if id(node) in memo:
            return memo[id(node)]
        if isinstance(node, dict):
            out_d: dict = {}
            memo[id(node)] = out_d
            for k, v in node.items():
                out_d[str(k).lower() if isinstance(k, bool) else str(k)] = _plain_data(v, memo)
            return out_d
        out_l: list = []
        memo[id(node)] = out_l
        out_l.extend(_plain_data(v, memo) for v in node)
        return out_l
    if isinstance(node, (_dt.date, _dt.datetime)):
        return node.isoformat()
    return node


def _looks_like_spec(data: Any) -> bool:
    return isinstance(data, dict) and (
        "openapi" in data or "swagger" in data or isinstance(data.get("paths"), dict)
    )


def parse_spec_text(text: str) -> tuple[Optional[dict], str]:
    """Parse JSON or YAML text. Returns (spec, reason); reason explains a None."""
    if text.lstrip()[:1] == "<":
        return None, "body is HTML or XML, not a spec"
    try:
        data: Any = json.loads(text)
    except ValueError:
        try:
            data = _plain_data(yaml.safe_load(text))
        except yaml.YAMLError as e:
            first = str(e).splitlines()[0] if str(e) else "parse error"
            return None, f"body isn't valid JSON or YAML ({first})"
        except RecursionError:
            return None, "YAML document is nested too deeply"
    if not isinstance(data, dict):
        return None, f"parsed, but isn't an object (got {type(data).__name__})"
    if not _looks_like_spec(data):
        return None, f"parsed, but has no paths/swagger/openapi key (keys: {list(data)[:8]})"
    return data, ""


_SPEC_REF_PATTERNS = (
    re.compile(r"""spec-url\s*=\s*["']([^"']+)["']""", re.I),               # ReDoc tag
    re.compile(r"""Redoc\.init\(\s*["']([^"']+)["']"""),                    # ReDoc JS
    re.compile(r"""data-url\s*=\s*["']([^"']+)["']""", re.I),               # Scalar
    re.compile(r"""(?<![\w-])["']?url["']?\s*[:=]\s*["']([^"']+)["']"""),   # SwaggerUIBundle({url}) and urls[]
    re.compile(r"""["']?configUrl["']?\s*[:=]\s*["']([^"']+)["']"""),       # springdoc
    re.compile(r"""["']?swaggerUrl["']?\s*[:=]\s*["']([^"']+)["']"""),      # swagger-ui-express
)
_EMBEDDED_SPEC = re.compile(r"""["']?(?:swaggerDoc|spec)["']?\s*[:=]\s*(?=\{)""")
# Pages also keep the URL in a variable or a lookup table instead of a `url:` literal.
# This is looser than the patterns above, so it only counts for the page's own origin.
_SPEC_LIKE_URL = re.compile(
    r"""(?:https?://[^\s"'`,;()<>]+|\.{0,2}/[^\s"'`,;()<>]*)"""
    r"""(?:openapi|swagger|api-docs)[^\s"'`,;()<>]*\.(?:json|ya?ml)""",
    re.I,
)
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)
_INIT_SCRIPT = re.compile(r"init|config|index|swagger-ui-settings|settings", re.I)
_LIBRARY_SCRIPT = re.compile(r"bundle|standalone|preset|\.min\.js", re.I)
_NOT_A_SPEC = re.compile(r"\.(css|js|png|jpe?g|svg|ico|woff2?|ttf|html?)(\?|#|$)", re.I)


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def spec_refs_from_body(text: str, page_url: str) -> list[str]:
    """Find spec URLs named by a docs page, an init script or a UI config object.

    Reading what the page declares beats guessing, and works however the page was
    configured: FastAPI, Swashbuckle, springdoc, swagger-ui-express, ReDoc, Scalar.
    """
    refs: list[str] = []

    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):  # a swagger-config response
        entries = [e for e in data.get("urls") or [] if isinstance(e, dict) and e.get("url")]
        # Swagger UI opens the group named by urls.primaryName, else the first.
        primary = data.get("urls.primaryName")
        entries.sort(key=lambda e: e.get("name") != primary)
        refs.extend(str(e["url"]) for e in entries)
        if isinstance(data.get("url"), str):
            refs.append(data["url"])
        return _resolve_refs(refs, page_url)
    if data is not None:
        return []

    unescaped = text.replace("\\/", "/").replace("\\u0026", "&").replace("&amp;", "&")
    for pattern in _SPEC_REF_PATTERNS:
        refs.extend(m.group(1) for m in pattern.finditer(unescaped))
    resolved = _resolve_refs(refs, page_url)
    # The stock Swagger UI initializer points at the Petstore demo. Only follow
    # that when the page really is hosted there.
    resolved = [r for r in resolved if "petstore" not in r.lower() or _same_origin(r, page_url)]
    loose = _resolve_refs((m.group(0) for m in _SPEC_LIKE_URL.finditer(unescaped)), page_url)
    resolved += [r for r in loose if _same_origin(r, page_url)]
    return list(dict.fromkeys(resolved))


def embedded_spec(text: str) -> Optional[dict]:
    """Extract a spec held inline by a page or init script.

    swagger-ui-express serves `var options = {"swaggerDoc": {...}}` and no spec URL
    at all. Only strict JSON is read, never executed, so anything else is skipped.
    """
    decoder = json.JSONDecoder()
    for m in _EMBEDDED_SPEC.finditer(text):
        try:
            value, _ = decoder.raw_decode(text, m.end())
        except ValueError:
            continue
        if _looks_like_spec(value):
            return value
    return None


def _resolve_refs(refs: Iterable[str], page_url: str) -> list[str]:
    out: list[str] = []
    for ref in refs:
        ref = ref.strip()
        if not ref or ref.startswith(("#", "data:", "javascript:")) or "{" in ref or "$" in ref:
            continue
        absolute = urljoin(page_url, ref)
        if absolute.lower().startswith(("http://", "https://")) and not _NOT_A_SPEC.search(absolute):
            out.append(absolute)
    return list(dict.fromkeys(out))


def init_scripts_from_html(text: str, page_url: str) -> list[str]:
    """Same-origin scripts on a docs page that may hold the UI configuration."""
    out: list[str] = []
    for m in _SCRIPT_SRC.finditer(text):
        src = m.group(1)
        name = src.split("?", 1)[0].rsplit("/", 1)[-1]
        if _INIT_SCRIPT.search(name) and not _LIBRARY_SCRIPT.search(name):
            absolute = urljoin(page_url, src)
            if _same_origin(absolute, page_url):
                out.append(absolute)
    return out


def fetch_spec(
    url: str,
    verify: bool = True,
    timeout: float = 15,
    headers: Optional[dict] = None,
    auth: Optional["Auth"] = None,
) -> tuple[dict, str]:
    """Locate and load a spec from a URL or a local file. Returns (spec, source).

    `headers`/`auth` support specs that sit behind authentication. They are only
    sent to the origin of the URL the user supplied, never to an origin that a
    fetched page merely referred to.
    """
    if is_local_source(url):
        path = _local_path(url)
        log.debug("fetch_spec: reading local file %s", path)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as e:
            raise SpecError(f"Could not read {path}: {e}") from e
        spec, reason = parse_spec_text(text)
        if spec is None:
            raise SpecError(f"{path} is not an OpenAPI/Swagger document: {reason}")
        return spec, path.resolve().as_uri()

    start = normalize_url(url)
    queue = deque(discover_spec_url(start))
    attempted: set[str] = set()
    declared: set[str] = set()
    # A spec without operations, such as an empty springdoc group, is kept only
    # until a URL the pages declared turns out to have some.
    empty: Optional[tuple[dict, str]] = None
    last_err = ""
    auth_required: Optional[str] = None
    tried = 0
    log.debug("fetch_spec: %d candidate(s) for %s", len(queue), redact_url(start))
    with requests.Session() as session:
        while queue and tried < _MAX_SPEC_REQUESTS:
            candidate = queue.popleft()
            if candidate in attempted:
                continue
            if empty and candidate not in declared:
                break
            attempted.add(candidate)
            tried += 1
            req_headers = {"Accept": "application/json, application/yaml, text/yaml, */*"}
            query: list = []
            cookies: dict = {}
            if _same_origin(candidate, start):
                req_headers.update(headers or {})
                if auth:
                    auth.apply(req_headers, query, cookies)
            target = candidate
            if query:
                target += ("&" if "?" in target else "?") + urlencode(query)
            secret = auth.token if auth else ""
            try:
                r = session.get(target, headers=req_headers, cookies=cookies or None,
                                timeout=timeout, verify=verify)
            except requests.exceptions.SSLError as e:
                raise SpecError(
                    f"TLS verification failed for {redact_url(candidate)}: {scrub_error(e, target, secret)}. If this is a "
                    "self-signed dev certificate, turn off TLS verification."
                ) from e
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                detail = scrub_error(e, target, secret)
                log.debug("fetch_spec: ERROR %s -> %s", redact_url(candidate), detail)
                last_err = f"{redact_url(candidate)} -> {detail}"
                # Every other candidate on this host would stall the same way.
                host = urlsplit(candidate).netloc
                queue = deque(c for c in queue if urlsplit(c).netloc != host)
                continue
            except requests.RequestException as e:
                detail = scrub_error(e, target, secret)
                log.debug("fetch_spec: ERROR %s -> %s", redact_url(candidate), detail)
                last_err = f"{redact_url(candidate)} -> {detail}"
                continue

            ctype = r.headers.get("Content-Type", "?")
            if r.status_code in (401, 403):
                auth_required = auth_required or candidate
            if r.status_code != 200:
                log.debug("fetch_spec: %s %s", r.status_code, redact_url(candidate))
                if not last_err:
                    last_err = f"{redact_url(candidate)} -> HTTP {r.status_code}"
                continue

            _default_utf8(r)
            spec, reason = parse_spec_text(r.text)
            how = f"content-type: {ctype}"
            if spec is None:
                spec, how = embedded_spec(r.text), "spec embedded in the page"
            if spec is not None:
                if has_operations(spec):
                    log.debug("fetch_spec: OK %s (%s)", redact_url(candidate), how)
                    return spec, r.url
                log.debug("fetch_spec: %s has no operations; trying the other declared URLs", redact_url(candidate))
                empty = empty or (spec, r.url)
                continue

            refs = spec_refs_from_body(r.text, r.url)
            if "html" in ctype.lower():
                refs += init_scripts_from_html(r.text, r.url)
            fresh = [ref for ref in refs if ref not in attempted]
            if fresh:
                log.debug("fetch_spec: %s names %s", redact_url(candidate), fresh)
                # What a page declares beats any guess. A duplicate left further
                # back in the queue is skipped once it has been attempted.
                queue.extendleft(reversed(fresh))
                declared.update(fresh)
            else:
                log.debug("fetch_spec: SKIP %s -> %s", redact_url(candidate), reason)
                last_err = f"{redact_url(candidate)} returned 200 but {reason}"

    if empty:
        log.debug("fetch_spec: OK %s (no operations in any declared spec)", redact_url(empty[1]))
        return empty
    if auth_required:
        raise SpecError(
            f"{redact_url(auth_required)} needs authentication to read the spec. "
            "Supply credentials, or point at a local copy of the spec file."
        )
    raise SpecError(
        f"Could not find an OpenAPI/Swagger spec near {redact_url(start)} "
        f"(tried {tried} location(s)). Last: {last_err or 'nothing responded'}. "
        "If you know where it is, paste the JSON/YAML URL or a file path directly."
    )


def spec_title(spec: dict) -> str:
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    return f"{info.get('title', 'API')} {info.get('version', '')}".strip()


def spec_version_label(spec: dict) -> str:
    if spec.get("openapi"):
        return f"OpenAPI {spec['openapi']}"
    if spec.get("swagger"):
        return f"Swagger {spec['swagger']}"
    return "unknown spec version"


# ---------------------------------------------------------------------------
# Spec parsing: one Endpoint shape for Swagger 2.0 and OpenAPI 3.x
# ---------------------------------------------------------------------------


@dataclass
class Endpoint:
    method: str
    path: str
    operation_id: str
    summary: str
    description: str
    tags: list[str]
    parameters: list[dict]
    request_body: Optional[dict]
    raw: dict = field(repr=False)
    deprecated: bool = False
    responses: dict = field(default_factory=dict, repr=False)
    security: Optional[list] = field(default=None, repr=False)

    @property
    def key(self) -> tuple[str, str]:
        return (self.method, self.path)


def resolve_ref(ref: str, spec: dict) -> dict:
    """Follow a local JSON pointer such as #/components/schemas/Pet."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref[2:].split("/"):
        part = unquote(part).replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def deref(node: Any, spec: dict, limit: int = 16) -> Any:
    """Follow $ref chains, with a limit so a self-referencing $ref can't loop."""
    while isinstance(node, dict) and "$ref" in node and limit > 0:
        node = resolve_ref(node["$ref"], spec)
        limit -= 1
    return node


def _pick_content_type(content: dict) -> str:
    if "application/json" in content:
        return "application/json"
    for ct in content:
        if "json" in ct.lower():
            return ct
    return next(iter(content), "application/json")


def _openapi3_body(rb: Any, spec: dict) -> Optional[dict]:
    rb = deref(rb, spec)
    if not isinstance(rb, dict):
        return None
    content = rb.get("content") if isinstance(rb.get("content"), dict) else {}
    ct = _pick_content_type(content)
    media = {name: m if isinstance(m, dict) else {} for name, m in content.items()}
    chosen = media.get(ct, {})
    return {
        "content_type": ct,
        "content_types": list(content) or [ct],
        "schema": chosen.get("schema"),
        "schemas": {name: m.get("schema") for name, m in media.items()},
        "media": media,
        "required": bool(rb.get("required", False)),
    }


def _swagger2_form_body(form_params: list[dict], consumes: list[str]) -> dict:
    has_file = any(p.get("type") == "file" for p in form_params)
    if has_file:
        ct = "multipart/form-data"
    elif consumes:
        ct = consumes[0]
    else:
        ct = "application/x-www-form-urlencoded"
    props: dict = {}
    required: list[str] = []
    for p in form_params:
        name = p.get("name", "")
        sub = {k: v for k, v in p.items() if k not in ("name", "in", "required")}
        if sub.get("type") == "file":
            sub = {"type": "string", "format": "binary", "description": p.get("description", "")}
        props[name] = sub
        if p.get("required"):
            required.append(name)
    schema = {"type": "object", "properties": props, "required": required}
    return {
        "content_type": ct,
        "content_types": [ct],
        "schema": schema,
        "schemas": {ct: schema},
        "media": {},
        "required": bool(required),
    }


def parse_endpoints(spec: dict) -> list[Endpoint]:
    eps: list[Endpoint] = []
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    top_consumes = spec.get("consumes") if isinstance(spec.get("consumes"), list) else []
    for path, item in paths.items():
        item = deref(item, spec)
        if not isinstance(item, dict):
            continue
        common = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            own = op.get("parameters") if isinstance(op.get("parameters"), list) else []
            # An operation parameter overrides a path-level one with the same name and location.
            merged: dict[tuple, dict] = {}
            for p in list(common) + list(own):
                p = deref(p, spec)
                if isinstance(p, dict) and p:
                    merged[(p.get("name"), p.get("in"))] = p
            params = list(merged.values())

            req_body = None
            if "requestBody" in op:
                req_body = _openapi3_body(op["requestBody"], spec)
            else:
                consumes = op.get("consumes") if isinstance(op.get("consumes"), list) else top_consumes
                body_params = [p for p in params if p.get("in") == "body"]
                form_params = [p for p in params if p.get("in") == "formData"]
                if body_params:
                    bp = body_params[0]
                    ct = _pick_content_type({c: {} for c in consumes}) if consumes else "application/json"
                    req_body = {
                        "content_type": ct,
                        "content_types": list(consumes) or [ct],
                        "schema": bp.get("schema"),
                        "schemas": {c: bp.get("schema") for c in (consumes or [ct])},
                        "media": {},
                        "required": bool(bp.get("required", False)),
                    }
                elif form_params:
                    req_body = _swagger2_form_body(form_params, consumes)
                params = [p for p in params if p.get("in") not in ("body", "formData")]

            tags = op.get("tags") if isinstance(op.get("tags"), list) and op.get("tags") else ["(default)"]
            eps.append(Endpoint(
                method=method.upper(),
                path=str(path),
                operation_id=str(op.get("operationId") or ""),
                summary=str(op.get("summary") or ""),
                description=str(op.get("description") or ""),
                tags=[str(t) for t in tags],
                parameters=params,
                request_body=req_body,
                raw=op,
                deprecated=bool(op.get("deprecated", False)),
                responses=op.get("responses") if isinstance(op.get("responses"), dict) else {},
                security=op.get("security") if isinstance(op.get("security"), list) else None,
            ))
    return eps


def has_operations(spec: dict) -> bool:
    """True when parse_endpoints would find at least one operation, without building them."""
    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    for item in paths.values():
        item = deref(item, spec)
        if isinstance(item, dict) and any(
            isinstance(op, dict) and str(method).lower() in HTTP_METHODS for method, op in item.items()
        ):
            return True
    return False


def find_endpoint(eps: list[Endpoint], method: str, path: str) -> Optional[Endpoint]:
    method = method.upper()
    return next((e for e in eps if e.method == method and e.path == path), None)


def filter_endpoints(
    eps: list[Endpoint],
    text: Optional[str] = None,
    tag: Optional[str] = None,
    method: Optional[str] = None,
) -> list[Endpoint]:
    """Case-insensitive filter over method, path, summary, tags and operationId."""
    out = eps
    if text:
        needle = text.lower()
        out = [
            e for e in out
            if needle in f"{e.method} {e.path} {e.summary} {e.operation_id} {' '.join(e.tags)}".lower()
        ]
    if tag:
        out = [e for e in out if tag.lower() in (t.lower() for t in e.tags)]
    if method:
        out = [e for e in out if e.method == method.upper()]
    return out


# ---------------------------------------------------------------------------
# Example bodies
# ---------------------------------------------------------------------------

_STRING_FORMATS = {
    "date-time": "2026-01-01T00:00:00Z",
    "date": "2026-01-01",
    "time": "00:00:00Z",
    "uuid": "00000000-0000-0000-0000-000000000000",
    "email": "user@example.com",
    "password": "",
    "uri": "https://example.com",
    "url": "https://example.com",
    "hostname": "example.com",
    "ipv4": "192.0.2.1",
    "ipv6": "2001:db8::1",
    "byte": "",
    "binary": "",
}

_FILE_PLACEHOLDER = "@/path/to/file"


def _schema_type(schema: dict) -> Optional[str]:
    """First non-null type. OpenAPI 3.1 allows a list such as ["string", "null"]."""
    t = schema.get("type")
    if isinstance(t, list):
        return next((x for x in t if x != "null"), None)
    return t


def example_from_schema(
    schema: Optional[dict],
    spec: dict,
    depth: int = 0,
    mode: str = "request",
    _stack: tuple = (),
) -> Any:
    """Build a plausible value from a schema.

    `mode` is "request" (skip readOnly properties) or "response" (skip writeOnly).
    A recursive schema stops at the point it would repeat instead of nesting until
    the depth limit, so tree-shaped models produce a short example.
    """
    if not isinstance(schema, dict) or not schema or depth > 12:
        return None
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in _stack:
            return None
        return example_from_schema(resolve_ref(ref, spec), spec, depth + 1, mode, _stack + (ref,))
    for key in ("example", "default", "const"):
        if key in schema:
            return schema[key]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]

    def recurse(sub: Any) -> Any:
        return example_from_schema(sub, spec, depth + 1, mode, _stack)

    if isinstance(schema.get("allOf"), list):
        merged: dict = {}
        scalar = None
        for sub in schema["allOf"]:
            v = recurse(sub)
            if isinstance(v, dict):
                merged.update(v)
            elif v is not None:
                scalar = v
        for name, sub in _visible_props(schema, spec, mode).items():
            merged[name] = recurse(sub)
        return merged if merged else scalar
    for key in ("oneOf", "anyOf"):
        choices = schema.get(key)
        if isinstance(choices, list) and choices:
            usable = [c for c in choices if not (isinstance(c, dict) and c.get("type") == "null")]
            return recurse((usable or choices)[0])

    t = _schema_type(schema)
    if t == "object" or "properties" in schema:
        out = {name: recurse(sub) for name, sub in _visible_props(schema, spec, mode).items()}
        extra = schema.get("additionalProperties")
        if not out and isinstance(extra, dict) and extra:
            out["key"] = recurse(extra)
        return out
    if t == "array":
        item = recurse(schema.get("items") or {})
        return [item] if item is not None else []
    if t == "string":
        return _STRING_FORMATS.get(schema.get("format", ""), "string")
    if t == "integer":
        return int(schema["minimum"]) if isinstance(schema.get("minimum"), (int, float)) else 0
    if t == "number":
        return schema["minimum"] if isinstance(schema.get("minimum"), (int, float)) else 0
    if t == "boolean":
        return False
    return None


def _visible_props(schema: dict, spec: dict, mode: str) -> dict:
    hidden = "readOnly" if mode == "request" else "writeOnly"
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    out = {}
    for name, sub in props.items():
        target = deref(sub, spec)
        if isinstance(target, dict) and target.get(hidden):
            continue
        if isinstance(sub, dict) and sub.get(hidden):
            continue
        out[name] = sub
    return out


def is_form_type(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return "x-www-form-urlencoded" in ct or "multipart/form-data" in ct


def is_json_type(content_type: str) -> bool:
    return "json" in (content_type or "").lower()


def example_body(ep: Endpoint, spec: dict, content_type: Optional[str] = None) -> Any:
    """Example request body for an endpoint, preferring examples the spec gives.

    In form bodies a leading `@` means "upload this local file", so text taken from
    the spec must never reach the wire in that form: a hostile spec could otherwise
    craft an example that uploads a file from the user's disk. Only the harmless
    placeholder is emitted, and only for fields declared as binary.
    """
    rb = ep.request_body or {}
    ct = content_type or rb.get("content_type") or "application/json"
    media = (rb.get("media") or {}).get(ct) or {}
    schema = (rb.get("schemas") or {}).get(ct) or rb.get("schema")

    value: Any = None
    found = False
    if isinstance(media, dict) and "example" in media:
        value, found = media["example"], True
    elif isinstance(media, dict) and isinstance(media.get("examples"), dict) and media["examples"]:
        first = deref(next(iter(media["examples"].values())), spec)
        if isinstance(first, dict) and "value" in first:
            value, found = first["value"], True
    if not found:
        value = example_from_schema(schema, spec)

    if is_form_type(ct) and isinstance(value, dict):
        target = deref(schema, spec) or {}
        props = _collect_props(target, spec)
        clean: dict = {}
        for k, v in value.items():
            sub = deref(props.get(k), spec) or {}
            if _is_file_schema(sub):
                clean[k] = _FILE_PLACEHOLDER
            elif isinstance(v, str):
                clean[k] = v.lstrip("@")
            else:
                clean[k] = v
        return clean
    return value


def _is_file_schema(schema: Any) -> bool:
    """OpenAPI 3.0 and Swagger mark uploads with format: binary; 3.1 uses contentMediaType."""
    if not isinstance(schema, dict):
        return False
    if schema.get("format") == "binary":
        return True
    media = schema.get("contentMediaType")
    return isinstance(media, str) and not media.lower().startswith("text/")


def _collect_props(schema: dict, spec: dict, depth: int = 0) -> dict:
    props: dict = {}
    if not isinstance(schema, dict) or depth > 8:
        return props
    for sub in schema.get("allOf") or []:
        props.update(_collect_props(deref(sub, spec) or {}, spec, depth + 1))
    if isinstance(schema.get("properties"), dict):
        props.update(schema["properties"])
    return props


def body_text_for_editor(value: Any, content_type: str) -> str:
    """Render a body value as text the user can edit."""
    if value is None:
        return ""
    if isinstance(value, str) and not is_json_type(content_type) and not is_form_type(content_type):
        return value
    return json.dumps(value, indent=2, ensure_ascii=False)


def parse_body_text(text: str, content_type: str) -> Any:
    """Convert editor text into a value for execute_call. Raises ValueError.

    JSON and form bodies are written as JSON. Any other type is sent as raw text.
    """
    text = (text or "").strip()
    if not text:
        return None
    if is_json_type(content_type):
        try:
            return json.loads(text)
        except ValueError as e:
            raise ValueError(f"Body is not valid JSON: {e}") from e
    if is_form_type(content_type):
        try:
            value = json.loads(text)
        except ValueError as e:
            raise ValueError(f'Form bodies are written as a JSON object, e.g. {{"field": "value"}}: {e}') from e
        if not isinstance(value, dict):
            raise ValueError('Form bodies are written as a JSON object, e.g. {"field": "value"}.')
        return value
    return text


# ---------------------------------------------------------------------------
# Servers, parameters and URLs
# ---------------------------------------------------------------------------


def _expand_server_vars(server: dict) -> str:
    url = str(server.get("url") or "")
    variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}
    for name, var in variables.items():
        if isinstance(var, dict) and "default" in var:
            url = url.replace("{" + name + "}", str(var["default"]))
    return url


def server_urls(spec: dict, spec_url: str) -> list[str]:
    """Every base URL the spec declares, resolved against where it was loaded from.

    Returns [] for a spec loaded from a local file that only has relative servers,
    because the host is then unknown and the user has to supply one.
    """
    is_file = spec_url.lower().startswith("file:")
    out: list[str] = []

    servers = spec.get("servers") if isinstance(spec.get("servers"), list) else []
    for server in servers:
        if not (isinstance(server, dict) and server.get("url")):
            continue
        url = _expand_server_vars(server)
        if not re.match(r"^https?://", url, re.I):
            if is_file:
                continue
            url = urljoin(spec_url, url)
        out.append(url.rstrip("/"))

    if not servers:
        host = spec.get("host")
        base_path = str(spec.get("basePath") or "")
        if isinstance(host, str) and host:
            schemes = spec.get("schemes") if isinstance(spec.get("schemes"), list) else []
            own = urlsplit(spec_url).scheme.lower()
            if own in ("http", "https") and (not schemes or own in schemes):
                scheme = own
            else:
                scheme = schemes[0] if schemes else "https"
            out.append(f"{scheme}://{host}{base_path}".rstrip("/"))
        elif not is_file:
            parts = urlsplit(spec_url)
            out.append(f"{parts.scheme}://{parts.netloc}{base_path}".rstrip("/"))
    return list(dict.fromkeys(out))


def base_url_from_spec(spec: dict, spec_url: str) -> str:
    """The first declared base URL, or "" when it can't be known."""
    urls = server_urls(spec, spec_url)
    return urls[0] if urls else ""


def origins_differ(base: str, spec_url: str) -> bool:
    """True when the spec directs requests to a different host than it came from.

    A spec chooses its own `servers`, so this is what would send credentials to
    another host. Front ends surface it rather than letting it pass silently.
    """
    if not base or not spec_url.lower().startswith("http"):
        return False
    return urlsplit(base).netloc.lower() != urlsplit(spec_url).netloc.lower()


def param_schema(p: dict) -> dict:
    """A parameter's schema across Swagger 2.0 (inline) and OpenAPI 3.x shapes."""
    if not isinstance(p, dict):
        return {}
    if isinstance(p.get("schema"), dict):
        return p["schema"]
    content = p.get("content")
    if isinstance(content, dict) and content:
        media = next(iter(content.values()))
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return p


def param_type_label(p: dict, spec: Optional[dict] = None) -> str:
    schema = param_schema(p)
    if spec is not None:
        schema = deref(schema, spec) or {}
    t = _schema_type(schema) or ""
    if t == "array":
        items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        if spec is not None:
            items = deref(items, spec) or {}
        return f"array<{_schema_type(items) or 'any'}>"
    fmt = schema.get("format")
    return f"{t} ({fmt})" if t and fmt else str(t)


def param_enum(p: dict, spec: Optional[dict] = None) -> list[str]:
    """Allowed values of a parameter, as strings. Booleans offer true and false."""
    schema = param_schema(p)
    if spec is not None:
        schema = deref(schema, spec) or {}
    if isinstance(schema.get("enum"), list):
        return [_param_str(v) for v in schema["enum"]]
    if _schema_type(schema) == "boolean":
        return ["true", "false"]
    return []


def _param_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def default_param_value(p: dict, spec: Optional[dict] = None) -> Optional[str]:
    """A parameter's value as declared by the spec, or None if it declares none."""
    if not isinstance(p, dict):
        return None
    schema = param_schema(p)
    if spec is not None:
        schema = deref(schema, spec) or {}
    for source in (schema, p):
        for key in ("default", "example"):
            if key in source and source[key] is not None:
                return _param_str(source[key])
    examples = p.get("examples")
    if isinstance(examples, dict) and examples:
        first = next(iter(examples.values()))
        if spec is not None:
            first = deref(first, spec)
        if isinstance(first, dict) and first.get("value") is not None:
            return _param_str(first["value"])
    return None


def build_url(base: str, path: str, path_params: Optional[dict] = None) -> str:
    """Join base and path, percent-encoding path values so they stay one segment."""
    p = path
    for k, v in (path_params or {}).items():
        p = p.replace("{" + str(k) + "}", quote(str(v), safe=""))
    return base.rstrip("/") + ("" if p.startswith("/") else "/") + p


def with_query(url: str, query: Union[dict, list, None]) -> str:
    if not query:
        return url
    items = list(query.items()) if isinstance(query, dict) else list(query)
    return url + ("&" if "?" in url else "?") + urlencode(items, doseq=True)


_DELIMITERS = {"csv": ",", "ssv": " ", "tsv": "\t", "pipes": "|",
               "spaceDelimited": " ", "pipeDelimited": "|"}


def _encode_query_value(p: dict, name: str, value: str, spec: Optional[dict]) -> list[tuple[str, str]]:
    """Apply array serialisation. The user types array values comma-separated."""
    schema = param_schema(p)
    if spec is not None:
        schema = deref(schema, spec) or {}
    if _schema_type(schema) != "array":
        return [(name, value)]
    values = [v.strip() for v in value.split(",") if v.strip()]
    if "collectionFormat" in p or (p.get("type") == "array"):  # Swagger 2.0, default csv
        fmt = p.get("collectionFormat", "csv")
        explode = fmt == "multi"
        delimiter = _DELIMITERS.get(fmt, ",")
    else:  # OpenAPI 3.x, default style=form explode=true
        style = p.get("style", "form")
        explode = bool(p.get("explode", style == "form"))
        delimiter = _DELIMITERS.get(style, ",")
    if explode:
        return [(name, v) for v in values]
    return [(name, delimiter.join(values))]


@dataclass
class RequestParts:
    path_params: dict = field(default_factory=dict)
    query: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    missing: list = field(default_factory=list)


def split_param_values(ep: Endpoint, values: dict, spec: Optional[dict] = None) -> RequestParts:
    """Sort user-entered values into where the spec says they belong.

    `values` maps (name, location) or plain name to a string. A required parameter,
    or a `{placeholder}` in the path, that has no value is reported in `missing`.
    """
    parts = RequestParts()
    declared_path: set[str] = set()
    for p in ep.parameters:
        name, loc = p.get("name", ""), p.get("in", "")
        raw = values.get((name, loc), values.get(name))
        value = "" if raw is None else str(raw)
        if loc == "path":
            declared_path.add(name)
        if value == "":
            if p.get("required") or loc == "path":
                parts.missing.append(name)
            continue
        if loc == "path":
            parts.path_params[name] = value
        elif loc == "query":
            parts.query.extend(_encode_query_value(p, name, value, spec))
        elif loc == "header":
            parts.headers[name] = value
        elif loc == "cookie":
            parts.cookies[name] = value
    for name in re.findall(r"\{([^{}]+)\}", ep.path):
        if name not in declared_path:
            raw = values.get((name, "path"), values.get(name))
            if raw in (None, ""):
                parts.missing.append(name)
            else:
                parts.path_params[name] = str(raw)
    return parts


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@dataclass
class Auth:
    """How to authenticate a request.

    kind is "none", "bearer" (`Authorization: <prefix> <token>`), "basic", or
    "apikey" (`token` is sent as `name` in `location`: header, query or cookie).
    """

    kind: str = "none"
    token: str = ""
    prefix: str = "Bearer"
    username: str = ""
    password: str = ""
    name: str = "X-API-Key"
    location: str = "header"

    def apply(self, headers: dict, query: list, cookies: dict) -> None:
        """Add credentials, without overriding a header the caller set explicitly."""
        has_auth_header = any(k.lower() == "authorization" for k in headers)
        if self.kind == "bearer" and self.token:
            if not has_auth_header:
                prefix = self.prefix.strip()
                headers["Authorization"] = f"{prefix} {self.token}" if prefix else self.token
        elif self.kind == "basic" and (self.username or self.password):
            if not has_auth_header:
                raw = f"{self.username}:{self.password}".encode("utf-8")
                headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        elif self.kind == "apikey" and self.token and self.name:
            if self.location == "query":
                query.append((self.name, self.token))
            elif self.location == "cookie":
                cookies[self.name] = self.token
            else:
                headers.setdefault(self.name, self.token)


@dataclass
class SecurityScheme:
    key: str
    kind: str  # bearer | basic | apikey | oauth2 | openid | other
    name: str = ""
    location: str = ""
    prefix: str = ""
    token_url: str = ""
    description: str = ""

    def to_auth(self) -> Optional[Auth]:
        """A starting Auth config for this scheme (the secret is left blank)."""
        if self.kind in ("bearer", "oauth2", "openid"):
            return Auth(kind="bearer", prefix=self.prefix or "Bearer")
        if self.kind == "basic":
            return Auth(kind="basic")
        if self.kind == "apikey":
            return Auth(kind="apikey", name=self.name, location=self.location or "header")
        return None


def parse_security_schemes(spec: dict) -> list[SecurityScheme]:
    """Normalise Swagger 2.0 securityDefinitions and OpenAPI 3.x securitySchemes."""
    components = spec.get("components") if isinstance(spec.get("components"), dict) else {}
    raw = components.get("securitySchemes") or spec.get("securityDefinitions") or {}
    out: list[SecurityScheme] = []
    if not isinstance(raw, dict):
        return out
    for key, s in raw.items():
        s = deref(s, spec)
        if not isinstance(s, dict):
            continue
        t = str(s.get("type", "")).lower()
        desc = str(s.get("description") or "")
        if t == "http":
            http_scheme = str(s.get("scheme", "")).lower()
            if http_scheme == "basic":
                out.append(SecurityScheme(key, "basic", description=desc))
            else:
                out.append(SecurityScheme(key, "bearer", prefix=http_scheme.capitalize() or "Bearer", description=desc))
        elif t == "basic":
            out.append(SecurityScheme(key, "basic", description=desc))
        elif t == "apikey":
            name, loc = str(s.get("name", "")), str(s.get("in", "header"))
            if name.lower() == "authorization" and loc == "header":
                # Swagger 2.0 has no bearer type, so APIs model it this way.
                out.append(SecurityScheme(key, "bearer", prefix="Bearer", description=desc))
            else:
                out.append(SecurityScheme(key, "apikey", name=name, location=loc, description=desc))
        elif t == "oauth2":
            token_url = str(s.get("tokenUrl") or "")
            flows = s.get("flows") if isinstance(s.get("flows"), dict) else {}
            for flow_name in ("password", "clientCredentials", "authorizationCode"):
                flow = flows.get(flow_name)
                if isinstance(flow, dict) and flow.get("tokenUrl"):
                    token_url = str(flow["tokenUrl"])
                    break
            out.append(SecurityScheme(key, "oauth2", token_url=token_url, prefix="Bearer", description=desc))
        elif t == "openidconnect":
            out.append(SecurityScheme(key, "openid", prefix="Bearer", description=desc))
        else:
            out.append(SecurityScheme(key, "other", description=desc))
    return out


# ---------------------------------------------------------------------------
# Executing requests
# ---------------------------------------------------------------------------


@dataclass
class CallResult:
    method: str
    url: str
    status: int
    reason: str
    elapsed_ms: float
    headers: dict
    text: str
    json: Any = None
    error: Optional[str] = None
    content: bytes = field(default=b"", repr=False)
    request_headers: dict = field(default_factory=dict, repr=False)
    request_body: str = field(default="", repr=False)

    @property
    def size(self) -> int:
        return len(self.content) if self.content else len(self.text.encode("utf-8", "replace"))

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v
        return ""

    @property
    def is_binary(self) -> bool:
        """True when the body shouldn't be displayed as text."""
        if self.json is not None or not self.content:
            return False
        ct = self.content_type.lower().split(";")[0].strip()
        if ct.startswith("text/") or "json" in ct or "xml" in ct or "yaml" in ct or "javascript" in ct:
            return False
        return b"\x00" in self.content[:4096] or ct.startswith(("image/", "audio/", "video/", "application/octet"))


def _read_upload(ref: str) -> tuple[str, bytes]:
    path = os.path.expanduser(ref[1:])
    with open(path, "rb") as f:
        return os.path.basename(path), f.read()


def _form_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return "" if value is None else str(value)


def _request_kwargs(
    *,
    headers: Optional[dict],
    query: Union[dict, list, None],
    body: Any,
    content_type: Optional[str],
    auth: Optional[Auth],
    token: Optional[str],
    cookies: Optional[dict],
) -> tuple[dict, list]:
    """Translate the logical request into requests kwargs. May raise OSError."""
    h = dict(headers or {})
    q: list = list(query.items()) if isinstance(query, dict) else list(query or [])
    c = dict(cookies or {})
    effective = auth or (Auth(kind="bearer", token=token) if token else None)
    if effective:
        effective.apply(h, q, c)

    kwargs: dict = {"headers": h}
    if c:
        kwargs["cookies"] = c
    if body is None:
        return kwargs, q

    ct = content_type or next((v for k, v in h.items() if k.lower() == "content-type"), "application/json")
    if "multipart/form-data" in ct.lower():
        # requests must generate the boundary, so any explicit Content-Type goes.
        kwargs["headers"] = {k: v for k, v in h.items() if k.lower() != "content-type"}
        files: list = []
        items = body.items() if isinstance(body, dict) else []
        for name, value in items:
            for one in value if isinstance(value, list) else [value]:
                if isinstance(one, str) and one.startswith("@"):
                    filename, data = _read_upload(one)
                    files.append((name, (filename, data)))
                else:
                    files.append((name, (None, _form_text(one))))
        kwargs["files"] = files
    elif "x-www-form-urlencoded" in ct.lower():
        h.setdefault("Content-Type", ct)
        if isinstance(body, dict):
            pairs: list = []
            for name, value in body.items():
                for one in value if isinstance(value, list) else [value]:
                    pairs.append((name, _form_text(one)))
            kwargs["data"] = pairs
        else:
            kwargs["data"] = str(body).encode("utf-8")
    elif is_json_type(ct) and not isinstance(body, (bytes, bytearray)):
        h.setdefault("Content-Type", ct)
        kwargs["data"] = json.dumps(body, ensure_ascii=False).encode("utf-8")
    else:
        h.setdefault("Content-Type", ct)
        if isinstance(body, str) and body.startswith("@") and "octet-stream" in ct.lower():
            kwargs["data"] = _read_upload(body)[1]
        elif isinstance(body, (bytes, bytearray)):
            kwargs["data"] = bytes(body)
        else:
            kwargs["data"] = str(body).encode("utf-8")
    return kwargs, q


def execute_call(
    method: str,
    url: str,
    *,
    headers: Optional[dict] = None,
    query: Union[dict, list, None] = None,
    json_body: Any = None,
    body: Any = None,
    content_type: Optional[str] = None,
    token: Optional[str] = None,
    auth: Optional[Auth] = None,
    cookies: Optional[dict] = None,
    verify: bool = True,
    timeout: float = 30,
    session: Optional[requests.Session] = None,
) -> CallResult:
    """Send one request. Failures come back in CallResult.error rather than raising.

    `body` is encoded according to `content_type`: JSON, urlencoded form, multipart
    (a string value `@path` uploads that file) or raw text. `json_body` is shorthand
    for a JSON body. `token` is shorthand for `Auth(kind="bearer", token=token)`.

    Passing a `session` reuses its open connections, which saves a TCP and TLS
    handshake per call when many requests go to one host. Cookies the server sets
    are cleared from it afterwards, so one call never silently authenticates the next.
    """
    method = method.upper()
    payload = body if body is not None else json_body
    t0 = time.perf_counter()
    display_url = with_query(url, query)

    def failed(message: str, sent_url: str = display_url) -> CallResult:
        message = scrub_error(message, sent_url, auth.token if auth else "")
        log.debug("execute_call: ERROR %s %s -> %s", method, redact_url(display_redact(sent_url, auth)), message)
        return CallResult(method, display_redact(sent_url, auth), 0, "",
                          (time.perf_counter() - t0) * 1000, {}, "", error=message)

    try:
        kwargs, final_query = _request_kwargs(
            headers=headers, query=query, body=payload, content_type=content_type,
            auth=auth, token=token, cookies=cookies,
        )
    except OSError as e:
        return failed(f"Could not read upload file: {e}")
    full_url = with_query(url, final_query)
    log.debug("execute_call: %s %s auth=%s", method, redact_url(display_redact(full_url, auth)),
              (auth.kind if auth else "bearer" if token else "none"))
    try:
        r = (session or requests).request(method, full_url, timeout=timeout, verify=verify, **kwargs)
    except requests.RequestException as e:
        return failed(str(e), full_url)
    finally:
        if session is not None:
            session.cookies.clear()
    elapsed = (time.perf_counter() - t0) * 1000
    log.debug("execute_call: <- %s %s %.0fms", r.status_code, r.reason, elapsed)
    _default_utf8(r)
    try:
        body_json = r.json()
    except ValueError:
        body_json = None
    sent = r.request.body
    if isinstance(sent, (bytes, bytearray)):
        sent_text = bytes(sent[:65536]).decode("utf-8", "replace")
    else:
        sent_text = sent or ""
    return CallResult(
        method=method,
        url=display_redact(full_url, auth),
        status=r.status_code,
        reason=r.reason or "",
        elapsed_ms=elapsed,
        headers=dict(r.headers),
        text=r.text,
        json=body_json,
        content=r.content,
        request_headers=dict(r.request.headers),
        request_body=sent_text,
    )


def display_redact(url: str, auth: Optional[Auth]) -> str:
    """Remove an API key the tool itself put in the query, before showing the URL."""
    if not (auth and auth.kind == "apikey" and auth.location == "query" and auth.token):
        return url
    parts = urlsplit(url)
    pairs = [(k, "***" if k == auth.name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs, safe="*"), parts.fragment))


def to_curl(
    method: str,
    url: str,
    *,
    headers: Optional[dict] = None,
    query: Union[dict, list, None] = None,
    body: Any = None,
    content_type: Optional[str] = None,
    token: Optional[str] = None,
    auth: Optional[Auth] = None,
    cookies: Optional[dict] = None,
    verify: bool = True,
) -> str:
    """Render a request as a curl command (POSIX shell quoting).

    Uploads become `-F field=@path` and don't read the file, so a placeholder path
    can still be rendered. The output contains the real credentials.
    """
    ct = content_type or "application/json"
    files_mode = body is not None and "multipart/form-data" in ct.lower()
    h = dict(headers or {})
    q: list = list(query.items()) if isinstance(query, dict) else list(query or [])
    c = dict(cookies or {})
    effective = auth or (Auth(kind="bearer", token=token) if token else None)
    if effective:
        effective.apply(h, q, c)

    parts = ["curl", "-X", method.upper()]
    if not verify:
        parts.append("-k")
    parts.append(shlex.quote(with_query(url, q)))
    for k, v in h.items():
        if files_mode and k.lower() == "content-type":
            continue
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    if c:
        parts += ["-H", shlex.quote("Cookie: " + "; ".join(f"{k}={v}" for k, v in c.items()))]
    if body is not None:
        if files_mode:
            items = body.items() if isinstance(body, dict) else []
            for name, value in items:
                for one in value if isinstance(value, list) else [value]:
                    if isinstance(one, str) and one.startswith("@"):
                        parts += ["-F", shlex.quote(f"{name}={one}")]
                    else:
                        parts += ["--form-string", shlex.quote(f"{name}={_form_text(one)}")]
        else:
            if not any(k.lower() == "content-type" for k in h):
                parts += ["-H", shlex.quote(f"Content-Type: {ct}")]
            if "x-www-form-urlencoded" in ct.lower() and isinstance(body, dict):
                pairs = []
                for name, value in body.items():
                    for one in value if isinstance(value, list) else [value]:
                        pairs.append((name, _form_text(one)))
                data = urlencode(pairs)
            elif is_json_type(ct):
                data = json.dumps(body, ensure_ascii=False)
            else:
                data = str(body)
            parts += ["--data-raw", shlex.quote(data)]
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Response validation
# ---------------------------------------------------------------------------

_MAX_ISSUES = 25


def validate_schema(value: Any, schema: Any, spec: dict, path: str = "$", depth: int = 0) -> list[str]:
    """Check a value against a schema. Returns human-readable problems, [] if none.

    Covers the keywords that catch contract drift: type, nullable, enum, const,
    required, properties, additionalProperties, items, allOf/oneOf/anyOf and the
    common numeric, string and array limits. `format` is treated as an annotation,
    as JSON Schema itself recommends by default.
    """
    if not isinstance(schema, dict) or not schema or depth > 48:
        return []
    if "$ref" in schema:
        target = resolve_ref(schema["$ref"], spec)
        if not target:
            return []
        siblings = {k: v for k, v in schema.items() if k != "$ref"}
        issues = validate_schema(value, target, spec, path, depth + 1)
        return issues + validate_schema(value, siblings, spec, path, depth + 1)

    if value is None and (schema.get("nullable") or schema.get("x-nullable")):
        return []

    issues: list[str] = []

    types = schema.get("type")
    if types is not None:
        wanted = types if isinstance(types, list) else [types]
        if not any(_type_matches(value, t) for t in wanted):
            return [f"{path}: expected {'/'.join(map(str, wanted))}, got {_json_type(value)}"]

    if "const" in schema and value != schema["const"]:
        issues.append(f"{path}: expected constant {schema['const']!r}, got {value!r}")
    if isinstance(schema.get("enum"), list) and value not in schema["enum"]:
        issues.append(f"{path}: {value!r} is not one of {schema['enum'][:10]}")

    if isinstance(value, bool):
        pass
    elif isinstance(value, (int, float)):
        issues += _numeric_issues(value, schema, path)
    elif isinstance(value, str):
        issues += _string_issues(value, schema, path)

    if isinstance(value, dict):
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []
        for name in required:
            if name in value:
                continue
            target = deref(props.get(name), spec)
            if isinstance(target, dict) and target.get("writeOnly"):
                continue
            issues.append(f"{path}: missing required property '{name}'")
        extra = schema.get("additionalProperties")
        for name, sub_value in value.items():
            sub_path = f"{path}.{name}"
            if name in props:
                issues += validate_schema(sub_value, props[name], spec, sub_path, depth + 1)
            elif isinstance(extra, dict):
                issues += validate_schema(sub_value, extra, spec, sub_path, depth + 1)
            elif extra is False:
                issues.append(f"{path}: unexpected property '{name}'")
    elif isinstance(value, list):
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            issues.append(f"{path}: has {len(value)} item(s), minimum is {schema['minItems']}")
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            issues.append(f"{path}: has {len(value)} item(s), maximum is {schema['maxItems']}")
        items = schema.get("items")
        if isinstance(items, dict):
            for i, item in enumerate(value):
                issues += validate_schema(item, items, spec, f"{path}[{i}]", depth + 1)
                if len(issues) >= _MAX_ISSUES:
                    break

    if isinstance(schema.get("allOf"), list):
        for sub in schema["allOf"]:
            issues += validate_schema(value, sub, spec, path, depth + 1)
    if isinstance(schema.get("anyOf"), list) and schema["anyOf"]:
        if not any(not validate_schema(value, sub, spec, path, depth + 1) for sub in schema["anyOf"]):
            issues.append(f"{path}: doesn't match any of the anyOf schemas")
    if isinstance(schema.get("oneOf"), list) and schema["oneOf"]:
        matches = sum(1 for sub in schema["oneOf"] if not validate_schema(value, sub, spec, path, depth + 1))
        if matches != 1:
            issues.append(f"{path}: matches {matches} oneOf schemas, expected exactly 1")
    return issues[:_MAX_ISSUES]


def _numeric_issues(value: Union[int, float], schema: dict, path: str) -> list[str]:
    issues = []
    low, high = schema.get("minimum"), schema.get("maximum")
    excl_low, excl_high = schema.get("exclusiveMinimum"), schema.get("exclusiveMaximum")
    if isinstance(low, (int, float)) and (value <= low if excl_low is True else value < low):
        issues.append(f"{path}: {value} is below the minimum {low}")
    if isinstance(high, (int, float)) and (value >= high if excl_high is True else value > high):
        issues.append(f"{path}: {value} is above the maximum {high}")
    # OpenAPI 3.1 writes exclusive limits as numbers.
    if isinstance(excl_low, (int, float)) and not isinstance(excl_low, bool) and value <= excl_low:
        issues.append(f"{path}: {value} must be greater than {excl_low}")
    if isinstance(excl_high, (int, float)) and not isinstance(excl_high, bool) and value >= excl_high:
        issues.append(f"{path}: {value} must be less than {excl_high}")
    return issues


def _string_issues(value: str, schema: dict, path: str) -> list[str]:
    issues = []
    if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
        issues.append(f"{path}: length {len(value)} is under minLength {schema['minLength']}")
    if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
        issues.append(f"{path}: length {len(value)} is over maxLength {schema['maxLength']}")
    if isinstance(schema.get("pattern"), str):
        try:
            if not re.search(schema["pattern"], value):
                issues.append(f"{path}: doesn't match pattern {schema['pattern']}")
        except re.error:
            pass  # ECMA-262 syntax that Python's engine can't compile: skip, don't misreport.
    return issues


def _type_matches(value: Any, t: Any) -> bool:
    if t == "null":
        return value is None
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer()
        )
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "string":
        return isinstance(value, str)
    if t == "array":
        return isinstance(value, list)
    if t == "object":
        return isinstance(value, dict)
    return True


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def find_response_spec(ep: Endpoint, status: int, spec: dict) -> Optional[dict]:
    """The response documented for a status: exact code, then 2XX style, then default."""
    responses = ep.responses or {}
    wildcard = f"{status // 100}XX"
    for key in (str(status), wildcard, wildcard.lower(), "default"):
        if key in responses:
            resolved = deref(responses[key], spec)
            return resolved if isinstance(resolved, dict) else {}
    return None


def response_schema(response: dict, content_type: str = "") -> Optional[dict]:
    """A documented response's schema, for Swagger 2.0 and OpenAPI 3.x shapes."""
    if isinstance(response.get("schema"), dict):
        return response["schema"]
    content = response.get("content")
    if not isinstance(content, dict) or not content:
        return None
    actual = (content_type or "").split(";")[0].strip().lower()
    for name, media in content.items():
        if name.lower() == actual and isinstance(media, dict):
            return media.get("schema")
    if actual and not any(fnmatch_media(name, actual) for name in content):
        return None  # A different media type than documented; its schema doesn't apply.
    for name, media in content.items():
        if fnmatch_media(name, actual or name) and isinstance(media, dict):
            return media.get("schema")
    return None


def fnmatch_media(pattern: str, actual: str) -> bool:
    pattern = pattern.split(";")[0].strip().lower()
    if pattern in ("*/*", actual):
        return True
    return pattern.endswith("/*") and actual.startswith(pattern[:-1])


def validate_response(ep: Endpoint, result: CallResult, spec: dict) -> list[str]:
    """Compare a response with the spec. Returns contract problems, [] if none."""
    if result.error or result.status == 0 or not ep.responses:
        return []
    documented = find_response_spec(ep, result.status, spec)
    if documented is None:
        codes = ", ".join(sorted(ep.responses)) or "none"
        return [f"status {result.status} isn't documented (documented: {codes})"]
    schema = response_schema(documented, result.content_type)
    if not schema or result.json is None:
        if schema and is_json_type(result.content_type) and result.text.strip():
            return ["response claims to be JSON but couldn't be parsed"]
        return []
    return validate_schema(result.json, schema, spec)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

_TOKEN_KEYS = (
    "access_token", "accesstoken", "access", "token", "id_token", "idtoken", "jwt",
    "auth_token", "authtoken", "bearer", "session_token", "sessiontoken", "api_token",
    "apitoken", "key",
)
_NOT_A_TOKEN = {"refresh", "refresh_token", "refreshtoken"}


def extract_token(response_json: Any, dotted_path: Optional[str] = None) -> Optional[str]:
    """Find the bearer token in a login response.

    An explicit dotted path wins. Otherwise common field names are searched at any
    depth, shallowest first, so envelopes such as {data: {...}} or {result: {...}}
    work without per-backend configuration.
    """
    if dotted_path:
        node: Any = response_json
        for part in dotted_path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return None
        return node if isinstance(node, str) and node else None

    level = [response_json]
    for _ in range(6):
        next_level: list = []
        for node in level:
            if not isinstance(node, dict):
                continue
            lowered = {str(k).lower(): v for k, v in node.items()}
            for key in _TOKEN_KEYS:
                value = lowered.get(key)
                if isinstance(value, str) and value:
                    return value
            for k, v in lowered.items():
                if k not in _NOT_A_TOKEN and isinstance(v, dict):
                    next_level.append(v)
        if not next_level:
            break
        level = next_level
    return None


@dataclass
class LoginResult:
    token: Optional[str]
    status: int
    body: Any
    cookies: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """A token was issued, or the server opened a cookie session."""
        return bool(self.token) or (200 <= self.status < 300 and bool(self.cookies))


def resolve_auth_url(base_url: str, auth_path: str) -> str:
    """An absolute auth URL is used as is; a path is resolved against the host root."""
    if re.match(r"^https?://", auth_path, re.I):
        return auth_path
    parts = urlsplit(normalize_url(base_url))
    return f"{parts.scheme}://{parts.netloc}/{auth_path.lstrip('/')}"


def login(
    base_url: str,
    username: str,
    password: str,
    *,
    auth_path: str,
    username_field: str = "username",
    password_field: str = "password",
    extra_fields: Optional[dict] = None,
    form: bool = False,
    token_path: Optional[str] = None,
    headers: Optional[dict] = None,
    verify: bool = True,
    timeout: float = 15,
    body_override: Optional[dict] = None,
) -> LoginResult:
    """POST credentials to an auth endpoint and capture what the server issues.

    Works with JSON or form-encoded logins (`form=True`, as OAuth2's password grant
    requires), and with a token in the body, an `Authorization` response header, or
    a cookie session. `body_override` replaces the generated payload entirely.
    """
    auth_url = resolve_auth_url(base_url, auth_path)
    if body_override is not None:
        body = body_override
    else:
        body = {username_field: username, password_field: password, **(extra_fields or {})}
    log.debug("login: POST %s body_keys=%s form=%s", redact_url(auth_url), list(body), form)
    send = {"data": body} if form else {"json": body}
    r = requests.post(auth_url, headers=headers or None, timeout=timeout, verify=verify, **send)
    log.debug("login: <- %s %s (content-type: %s)", r.status_code, r.reason, r.headers.get("Content-Type", "?"))
    _default_utf8(r)
    try:
        data: Any = r.json()
    except ValueError:
        data = {"status": r.status_code, "text": r.text[:4000]}
    if r.status_code >= 400:
        return LoginResult(None, r.status_code, data)

    token = extract_token(data, token_path)
    if token is None:
        header = r.headers.get("Authorization", "")
        if header:
            token = header.split(" ", 1)[1].strip() if " " in header else header.strip()
    cookies = dict(r.cookies)
    if token is None and not cookies:
        keys = list(data) if isinstance(data, dict) else type(data).__name__
        log.debug("login: 2xx but no token or cookie found. Response keys: %s", keys)
    return LoginResult(token, r.status_code, data, cookies)


_LOGIN_PATH = re.compile(r"(^|[/_.-])(log-?in|sign-?in|token|authenticate|auth|session|sessions|oauth)([/_.-]|$)", re.I)
_NOT_LOGIN_PATH = re.compile(
    r"refresh|verify|validate|revoke|introspect|log-?out|sign-?out|sign-?up|register|reset|forgot|"
    r"confirm|otp|callback|authorize|password|change|me$",
    re.I,
)
_USERNAME_FIELDS = ("username", "user_name", "userName", "email", "emailAddress", "email_address",
                    "login", "user", "phone", "phoneNumber", "phone_number", "mobile", "account", "identifier")
_PASSWORD_FIELDS = ("password", "passwd", "pwd", "pass", "secret")


def find_login_candidates(eps: list[Endpoint], spec: Optional[dict] = None) -> list[str]:
    """Likely login endpoints: declared OAuth2 token URLs, then POSTs named like one."""
    out: list[str] = []
    for scheme in parse_security_schemes(spec or {}):
        if scheme.token_url:
            out.append(scheme.token_url)
    scored: list[tuple[int, str]] = []
    for ep in eps:
        if ep.method != "POST" or _NOT_LOGIN_PATH.search(ep.path) or not _LOGIN_PATH.search(ep.path):
            continue
        score = 0 if re.search(r"log-?in|sign-?in", ep.path, re.I) else 1
        scored.append((score, ep.path))
    out.extend(path for _, path in sorted(scored, key=lambda s: (s[0], len(s[1]), s[1])))
    return list(dict.fromkeys(out))


@dataclass
class LoginShape:
    """What a login endpoint's own schema says about its request."""

    username_field: Optional[str] = None
    password_field: Optional[str] = None
    form: bool = False
    extra_required: list = field(default_factory=list)


def guess_login_shape(ep: Endpoint, spec: dict) -> LoginShape:
    shape = LoginShape()
    rb = ep.request_body
    if not rb:
        return shape
    shape.form = "x-www-form-urlencoded" in (rb.get("content_type") or "").lower()
    schema = deref(rb.get("schema"), spec)
    if not isinstance(schema, dict):
        return shape
    props = _collect_props(schema, spec)
    required: list = list(schema.get("required") or [])
    for sub in schema.get("allOf") or []:
        target = deref(sub, spec)
        if isinstance(target, dict):
            required += list(target.get("required") or [])
    by_lower = {name.lower(): name for name in props}
    for candidate in _USERNAME_FIELDS:
        if candidate.lower() in by_lower:
            shape.username_field = by_lower[candidate.lower()]
            break
    for candidate in _PASSWORD_FIELDS:
        if candidate.lower() in by_lower:
            shape.password_field = by_lower[candidate.lower()]
            break
    known = {shape.username_field, shape.password_field}
    shape.extra_required = [name for name in required if name not in known]
    return shape


def extract_field_errors(raw: Any) -> dict:
    """Pull {field: error} from common validation-error shapes.

    Understands {"errors": {...}} (ASP.NET ProblemDetails, Laravel), {"details": {...}},
    FastAPI's {"detail": [{"loc": [...], "msg": ...}]}, and a flat {field: [...]} body
    (Django REST Framework).
    """
    if not isinstance(raw, dict):
        return {}
    skip = {"status", "statuscode", "code", "message", "detail", "details", "non_field_errors",
            "succeeded", "success", "title", "type", "traceid", "instance", "error", "errors",
            "error_description", "text", "timestamp", "path"}
    detail = raw.get("detail")
    if isinstance(detail, list):
        out: dict = {}
        for item in detail:
            if isinstance(item, dict) and isinstance(item.get("loc"), list) and item["loc"]:
                out[str(item["loc"][-1])] = item.get("msg", "")
        if out:
            return out
    for key in ("errors", "details"):
        errs = raw.get(key)
        if isinstance(errs, dict) and errs:
            return {k: v for k, v in errs.items() if k.lower() not in skip}
    return {k: v for k, v in raw.items() if k.lower() not in skip and isinstance(v, (list, str))}


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@dataclass
class AuditRow:
    method: str
    path: str
    url: str
    status: int
    ms: float
    bucket: str  # ok | auth | client | server | error
    tag: str = ""
    error: Optional[str] = None
    issues: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "method": self.method, "path": self.path, "tag": self.tag, "status": self.status,
            "ms": round(self.ms), "bucket": self.bucket, "error": self.error, "issues": self.issues,
        }


def audit_bucket(status: int, error: Optional[str] = None) -> str:
    if error or status == 0:
        return "error"
    if status in (401, 403):
        return "auth"
    if status < 400:
        return "ok"
    return "client" if status < 500 else "server"


def plan_audit(
    eps: list[Endpoint],
    spec: Optional[dict] = None,
    *,
    params: Optional[dict] = None,
    tag: Optional[str] = None,
    text: Optional[str] = None,
    limit: Optional[int] = None,
) -> tuple[list[tuple[Endpoint, RequestParts]], list[dict]]:
    """Choose which GET endpoints can be called without inventing data.

    A required parameter is filled from `params` (by name), then from a value the
    spec declares. An endpoint still lacking one is skipped and reported. Guessing
    could hit the wrong record, and would just fail with a meaningless 4xx.
    """
    params = params or {}
    targets: list[tuple[Endpoint, RequestParts]] = []
    skipped: list[dict] = []
    for ep in filter_endpoints(eps, text=text, tag=tag, method="GET"):
        values: dict = {}
        for p in ep.parameters:
            name, loc = p.get("name", ""), p.get("in", "")
            if name in params:
                values[(name, loc)] = params[name]
            elif p.get("required") or loc == "path":
                declared = default_param_value(p, spec)
                if declared is not None:
                    values[(name, loc)] = declared
        for name in re.findall(r"\{([^{}]+)\}", ep.path):
            if name in params:
                values.setdefault((name, "path"), params[name])
        parts = split_param_values(ep, values, spec)
        if parts.missing:
            skipped.append({"method": ep.method, "path": ep.path, "missing": parts.missing})
        else:
            targets.append((ep, parts))
    if limit:
        targets = targets[:limit]
    return targets, skipped


def audit_one(
    ep: Endpoint,
    parts: RequestParts,
    base: str,
    *,
    spec: Optional[dict] = None,
    validate: bool = False,
    headers: Optional[dict] = None,
    auth: Optional[Auth] = None,
    cookies: Optional[dict] = None,
    verify: bool = True,
    timeout: float = 15,
    session: Optional[requests.Session] = None,
) -> AuditRow:
    """Call one planned endpoint and bucket the outcome.

    Share one `session` across an audit's calls so connections are reused.
    """
    url = build_url(base, ep.path, parts.path_params)
    res = execute_call(
        "GET", url,
        headers={**(headers or {}), **parts.headers},
        query=parts.query,
        cookies={**(cookies or {}), **parts.cookies},
        auth=auth,
        verify=verify,
        timeout=timeout,
        session=session,
    )
    issues = validate_response(ep, res, spec) if (validate and spec) else []
    return AuditRow(
        method=ep.method,
        path=ep.path,
        url=res.url,
        status=res.status,
        ms=res.elapsed_ms,
        bucket=audit_bucket(res.status, res.error),
        tag=ep.tags[0] if ep.tags else "",
        error=res.error,
        issues=issues,
    )


def run_audit(
    targets: list[tuple[Endpoint, RequestParts]],
    base: str,
    *,
    jobs: int = 1,
    **options: Any,
) -> Iterator[AuditRow]:
    """Call every planned endpoint, yielding rows in plan order.

    `jobs` above 1 keeps that many requests in flight. The default of 1 is
    deliberate: an audit shouldn't trip rate limits or load a server unasked.
    Each worker thread reuses its own connections. Closing the generator early
    cancels the calls that haven't started.
    """
    local = threading.local()
    sessions: list[requests.Session] = []
    lock = threading.Lock()

    def call(target: tuple[Endpoint, RequestParts]) -> AuditRow:
        session = getattr(local, "session", None)
        if session is None:
            session = local.session = requests.Session()
            with lock:
                sessions.append(session)
        ep, parts = target
        return audit_one(ep, parts, base, session=session, **options)

    try:
        if jobs <= 1:
            for target in targets:
                yield call(target)
            return
        with ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="specprobe-audit") as pool:
            futures = [pool.submit(call, target) for target in targets]
            try:
                for future in futures:
                    yield future.result()
            finally:
                for future in futures:
                    future.cancel()
    finally:
        with lock:
            for session in sessions:
                session.close()
