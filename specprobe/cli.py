"""Scriptable command line for testing any OpenAPI/Swagger API.

Subcommands:
    spec    list endpoints
    show    show one endpoint: parameters, example body, documented responses
    call    invoke one endpoint and print the response
    login   POST credentials to an auth endpoint and print the token
    audit   call every GET endpoint that needs no invented data, and summarize

Global flags go BEFORE the subcommand. Output on stdout is JSON unless --table
is passed; diagnostics go to stderr (add -v for a request trace).

Exit codes: 0 success, 1 failed call or failed audit check, 2 failed login or
bad usage.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import re
import sys
from typing import Any, Optional

from . import __version__
from .core import (
    Auth,
    Endpoint,
    base_url_from_spec,
    build_url,
    deref,
    default_param_value,
    example_body,
    execute_call,
    extract_field_errors,
    fetch_spec,
    filter_endpoints,
    find_endpoint,
    login,
    origins_differ,
    parse_endpoints,
    parse_security_schemes,
    param_type_label,
    plan_audit,
    run_audit,
    response_schema,
    spec_title,
    spec_version_label,
    split_param_values,
    to_curl,
    validate_response,
    example_from_schema,
)


class UsageError(Exception):
    """A problem with the command line itself. Reported with exit code 2."""


def _dump(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _pairs(items: Optional[list[str]], flag: str) -> list[tuple[str, str]]:
    """Parse repeated k=v flags, keeping order and duplicates."""
    out: list[tuple[str, str]] = []
    for item in items or []:
        if "=" not in item:
            raise UsageError(f"{flag} expects name=value, got {item!r}")
        k, v = item.split("=", 1)
        out.append((k.strip(), v))
    return out


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected a whole number, got {text!r}") from None
    if not 1 <= value <= 64:
        raise argparse.ArgumentTypeError("must be between 1 and 64")
    return value


def _auth(args) -> Optional[Auth]:
    if getattr(args, "api_key", None):
        name, value = _pairs([args.api_key], "--api-key")[0]
        return Auth(kind="apikey", name=name, token=value, location=args.api_key_in)
    if getattr(args, "basic", None):
        user, _, password = args.basic.partition(":")
        return Auth(kind="basic", username=user, password=password)
    token = getattr(args, "token", None) or os.environ.get("SPECPROBE_TOKEN")
    if token:
        return Auth(kind="bearer", token=token, prefix=args.token_prefix)
    return None


def _global_headers(args) -> dict:
    return dict(_pairs(getattr(args, "header", None), "--header"))


def _global_cookies(args) -> dict:
    return dict(_pairs(getattr(args, "cookie", None), "--cookie"))


def _load(args, groups: Optional[list] = None) -> tuple[dict, str, list[Endpoint], str]:
    spec, found = fetch_spec(
        args.url,
        verify=not args.no_verify,
        headers=_global_headers(args),
        auth=_auth(args),
        groups=groups,
    )
    base = args.base or base_url_from_spec(spec, found)
    eps = parse_endpoints(spec)
    return spec, found, eps, base


def _require_base(base: str) -> None:
    if not base:
        raise UsageError(
            "This spec doesn't say which host serves the API (it was loaded from a file "
            "with no absolute server URL). Pass --base https://host."
        )


def _warn_if_foreign(args, base: str, found: str) -> None:
    if not args.base and _auth(args) and origins_differ(base, found):
        _warn(f"the spec directs requests to {base}, a different host than it was loaded "
              "from. Your credentials will be sent there. Use --base to override.")


def _clean_path(path: str, flag: str) -> str:
    """Undo shell damage to a URL path.

    Git Bash rewrites `/x` arguments into Windows paths before we see them. That
    can't be reversed reliably, so explain it. Its workaround of writing `//x` can
    be accepted, by treating it as `/x`.
    """
    if os.environ.get("MSYSTEM") and re.match(r"^[A-Za-z]:[\\/]", path):
        raise UsageError(
            f"{flag} looks like Git Bash rewrote it into a Windows path ({path}). "
            "Set MSYS_NO_PATHCONV=1 for this command, or write the path with a double slash (//x)."
        )
    return "/" + path.lstrip("/") if path.startswith("//") else path


def _endpoint_summary(e: Endpoint, spec: dict) -> dict:
    return {
        "method": e.method,
        "path": e.path,
        "tags": e.tags,
        "operationId": e.operation_id,
        "summary": e.summary,
        "deprecated": e.deprecated,
        "has_body": bool(e.request_body),
        "body_content_types": (e.request_body or {}).get("content_types", []),
        "params": [
            {
                "name": p.get("name"),
                "in": p.get("in"),
                "required": bool(p.get("required", False)),
                "type": param_type_label(p, spec),
            }
            for p in e.parameters
        ],
    }


def cmd_spec(args) -> int:
    groups: list = []
    spec, found, eps, base = _load(args, groups)
    shown = filter_endpoints(eps, text=args.filter, tag=args.tag, method=args.method)
    if args.table:
        print(f"# {spec_title(spec)} ({spec_version_label(spec)})")
        print(f"# spec: {found}")
        for group in groups:
            mark = "*" if group.url == found else " "
            print(f"#  {mark} offered: {group.name}  {group.url}")
        print(f"# base: {base or '(unknown, pass --base)'}")
        schemes = parse_security_schemes(spec)
        if schemes:
            print("# auth: " + ", ".join(f"{s.key} ({s.kind})" for s in schemes))
        print(f"# {len(shown)} of {len(eps)} endpoints\n")
        width = max((len(e.method) for e in shown), default=4)
        for ep in sorted(shown, key=lambda e: (e.tags[0], e.path, e.method)):
            note = f"   -- {ep.summary}" if ep.summary else ""
            flag = " [deprecated]" if ep.deprecated else ""
            print(f"[{ep.tags[0]}] {ep.method:<{width}}  {ep.path}{flag}{note}")
        return 0
    _dump({
        "spec_url": found,
        "base_url": base,
        "info": spec.get("info", {}),
        "spec_version": spec_version_label(spec),
        "spec_groups": [vars(g) for g in groups],
        "security_schemes": [vars(s) for s in parse_security_schemes(spec)],
        "endpoints": [_endpoint_summary(e, spec) for e in shown],
    })
    return 0


def cmd_show(args) -> int:
    args.path = _clean_path(args.path, "--path")
    spec, _found, eps, _base = _load(args)
    ep = find_endpoint(eps, args.method, args.path)
    if not ep:
        raise UsageError(f"{args.method.upper()} {args.path} isn't in this spec. Try the spec subcommand.")
    responses: dict = {}
    for code, resp in ep.responses.items():
        documented = _resolve_response(resp, spec)
        schema = response_schema(documented)
        responses[code] = {
            "description": documented.get("description", ""),
            "example": example_from_schema(schema, spec, mode="response") if schema else None,
        }
    payload = _endpoint_summary(ep, spec)
    payload["description"] = ep.description
    payload["params"] = [
        {**row, "description": p.get("description", ""), "default": default_param_value(p, spec)}
        for row, p in zip(payload["params"], ep.parameters)
    ]
    if ep.request_body:
        payload["body_example"] = example_body(ep, spec)
    payload["responses"] = responses
    _dump(payload)
    return 0


def _resolve_response(resp: Any, spec: dict) -> dict:
    resolved = deref(resp, spec)
    return resolved if isinstance(resolved, dict) else {}


def _read_body(args, ep: Optional[Endpoint], spec: dict) -> tuple[Any, Optional[str]]:
    """Work out the request body and its content type from the call flags."""
    declared = (ep.request_body or {}).get("content_type") if ep else None
    content_type = args.content_type or declared

    if args.json_body is not None:
        try:
            return json.loads(args.json_body), args.content_type or "application/json"
        except ValueError as e:
            raise UsageError(f"--json-body isn't valid JSON: {e}") from e
    if args.json_file:
        try:
            with open(args.json_file, "r", encoding="utf-8-sig") as f:
                return json.load(f), args.content_type or "application/json"
        except (OSError, ValueError) as e:
            raise UsageError(f"--json-file: {e}") from e
    if args.body is not None:
        return args.body, content_type or "text/plain"
    if args.form:
        form: dict = {}
        for k, v in _pairs(args.form, "--form"):
            if k in form:
                form[k] = (form[k] if isinstance(form[k], list) else [form[k]]) + [v]
            else:
                form[k] = v
        has_file = any(
            str(one).startswith("@")
            for value in form.values()
            for one in (value if isinstance(value, list) else [value])
        )
        default_ct = "multipart/form-data" if has_file else "application/x-www-form-urlencoded"
        ct = args.content_type or (declared if declared and "form" in declared else default_ct)
        return form, ct
    if args.example and ep and ep.request_body:
        return example_body(ep, spec, content_type), content_type
    return None, content_type


def cmd_call(args) -> int:
    args.path = _clean_path(args.path, "--path")
    spec, found, eps, base = _load(args)
    _require_base(base)
    _warn_if_foreign(args, base, found)

    ep = find_endpoint(eps, args.method, args.path)
    if ep is None:
        _warn(f"{args.method.upper()} {args.path} isn't in the spec; sending it anyway.")

    query_pairs = _pairs(args.query, "--query")
    given_path = dict(_pairs(args.path_param, "--path-param"))
    headers = _global_headers(args)
    cookies = _global_cookies(args)
    query: list = list(query_pairs)

    if ep is not None:
        values: dict = {(name, "path"): value for name, value in given_path.items()}
        # Repeated --query flags are sent verbatim. A single value goes through the
        # spec's serialisation, so array parameters get their declared format.
        names = [k for k, _ in query_pairs]
        single = {k: v for k, v in query_pairs if names.count(k) == 1}
        for p in ep.parameters:
            name, loc = p.get("name", ""), p.get("in", "")
            if loc == "query" and name in single:
                values[(name, loc)] = single[name]
            elif loc == "path" and (name, loc) not in values:
                declared = default_param_value(p, spec)
                if declared is not None:
                    values[(name, loc)] = declared
            elif loc == "header":
                for k, v in headers.items():
                    if k.lower() == name.lower():
                        values[(name, loc)] = v
            elif loc == "cookie" and name in cookies:
                values[(name, loc)] = cookies[name]
        parts = split_param_values(ep, values, spec)
        path_missing = [
            name for name in parts.missing
            if ("{" + name + "}") in ep.path
        ]
        if path_missing:
            raise UsageError(
                f"Missing path parameter(s): {', '.join(path_missing)}. Use --path-param name=value."
            )
        given_path = {**given_path, **parts.path_params}
        spec_query_names = {p.get("name") for p in ep.parameters if p.get("in") == "query"}
        query = [(k, v) for k, v in query_pairs if not (k in single and k in spec_query_names)] + parts.query
        other_missing = [n for n in parts.missing if n not in path_missing and n not in dict(query_pairs)]
        if other_missing:
            _warn("required parameter(s) not supplied: " + ", ".join(other_missing))

    body, content_type = _read_body(args, ep, spec)
    url = build_url(base, args.path, given_path)

    if args.curl:
        print(to_curl(args.method, url, headers=headers, query=query, body=body,
                      content_type=content_type, auth=_auth(args), cookies=cookies,
                      verify=not args.no_verify))
        return 0

    res = execute_call(
        args.method, url,
        headers=headers,
        query=query,
        body=body,
        content_type=content_type,
        auth=_auth(args),
        cookies=cookies,
        verify=not args.no_verify,
        timeout=args.timeout,
    )
    issues = validate_response(ep, res, spec) if (args.validate and ep) else []
    ok = res.error is None and 200 <= res.status < 400 and not issues

    if args.output and res.error is None:
        with open(args.output, "wb") as f:
            f.write(res.content or res.text.encode("utf-8"))

    if args.raw:
        if res.error:
            print(res.error, file=sys.stderr)
        elif not args.output:
            print(res.text)
        for issue in issues:
            _warn(issue)
        return 0 if ok else 1

    if res.is_binary:
        shown: Any = f"<binary, {res.size} bytes; use --output FILE to save>"
    else:
        shown = res.json if res.json is not None else res.text
    summary: dict = {
        "method": res.method,
        "url": res.url,
        "status": res.status,
        "reason": res.reason,
        "elapsed_ms": round(res.elapsed_ms, 1),
        "headers": res.headers if args.full_headers else {
            k: v for k, v in res.headers.items()
            if k.lower() in ("content-type", "content-length", "www-authenticate", "location")
        },
        "body": shown,
        "error": res.error,
    }
    if args.validate:
        summary["contract_issues"] = issues
    if args.output and res.error is None:
        summary["saved_to"] = args.output
    _dump(summary)
    return 0 if ok else 1


def _read_password(args) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    if args.password is not None:
        return args.password
    env = os.environ.get("SPECPROBE_PASSWORD")
    if env is not None:
        return env
    if sys.stdin.isatty():
        return getpass.getpass("Password: ")
    raise UsageError("No password. Use --password-stdin, $SPECPROBE_PASSWORD or --password.")


def cmd_login(args) -> int:
    args.auth_path = _clean_path(args.auth_path, "--auth-path")
    result = login(
        args.url,
        args.username,
        _read_password(args),
        auth_path=args.auth_path,
        username_field=args.username_field,
        password_field=args.password_field,
        extra_fields=dict(_pairs(args.extra, "--extra")),
        form=args.form,
        token_path=args.token_path,
        headers=_global_headers(args),
        verify=not args.no_verify,
        timeout=args.timeout,
    )
    if not result.ok:
        payload: dict = {"ok": False, "status": result.status, "response": result.body}
        field_errors = extract_field_errors(result.body)
        if field_errors:
            payload["field_errors"] = field_errors
        _dump(payload)
        return 2
    if args.token_only:
        if not result.token:
            print("Login succeeded with a cookie session, so there's no token to print. "
                  "Re-run without --token-only to see the cookies.", file=sys.stderr)
            return 2
        print(result.token)
    else:
        _dump({"ok": True, "status": result.status, "token": result.token,
               "cookies": result.cookies, "response": result.body})
    return 0


_FAIL_BUCKETS = {
    "none": set(),
    "server": {"server", "error"},
    "client": {"client", "server", "error"},
    "any": {"auth", "client", "server", "error"},
}


def cmd_audit(args) -> int:
    spec, found, eps, base = _load(args)
    _require_base(base)
    _warn_if_foreign(args, base, found)
    targets, skipped = plan_audit(
        eps, spec,
        params=dict(_pairs(args.param, "--param")),
        tag=args.tag,
        text=args.filter,
        limit=args.limit,
    )
    print(f"# auditing {len(targets)} GET endpoint(s) against {base}; "
          f"{len(skipped)} skipped for missing required parameters", file=sys.stderr)

    counts = {"ok": 0, "auth": 0, "client": 0, "server": 0, "error": 0}
    rows = []
    contract_problems = 0
    options = dict(
        spec=spec,
        validate=args.validate,
        headers=_global_headers(args),
        auth=_auth(args),
        cookies=_global_cookies(args),
        verify=not args.no_verify,
        timeout=args.timeout,
    )
    for row in run_audit(targets, base, jobs=args.jobs, **options):
        counts[row.bucket] += 1
        if row.issues:
            contract_problems += 1
        rows.append(row)
        if args.table:
            err = f"  ({row.error})" if row.error else ""
            print(f"{row.bucket:<6} {row.status:<3} {round(row.ms):>5}ms  [{row.tag}] "
                  f"{row.method} {row.path}{err}", flush=True)
            for issue in row.issues:
                print(f"       contract: {issue}", flush=True)

    if args.table:
        for item in skipped:
            print(f"skip   ---     --    {item['method']} {item['path']}  "
                  f"(needs: {', '.join(item['missing'])})")
        print(f"\n# summary: {counts}"
              + (f", {contract_problems} with contract issues" if args.validate else ""),
              file=sys.stderr)
    else:
        _dump({
            "base": base,
            "counts": counts,
            "contract_problems": contract_problems,
            "results": [r.as_dict() for r in rows],
            "skipped": skipped,
        })

    failing = sum(counts[b] for b in _FAIL_BUCKETS[args.fail_on])
    if args.validate and args.fail_on != "none":
        failing += contract_problems
    return 1 if failing else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="specprobe",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--url", default=os.environ.get("SPECPROBE_URL"),
                   help="Spec URL, docs page, host root or local spec file (or $SPECPROBE_URL)")
    p.add_argument("--no-verify", action="store_true", help="Skip TLS verification (self-signed dev certs)")
    p.add_argument("--base", help="Override the server base URL inferred from the spec")
    p.add_argument("-v", "--verbose", action="store_true", help="Trace requests to stderr (secrets redacted)")

    auth = p.add_argument_group("authentication")
    auth.add_argument("--token", help="Bearer token (or $SPECPROBE_TOKEN)")
    auth.add_argument("--token-prefix", default="Bearer",
                      help='Authorization scheme for --token (default: Bearer; DRF TokenAuth uses "Token"; "" for none)')
    auth.add_argument("--basic", metavar="USER:PASS", help="HTTP Basic credentials")
    auth.add_argument("--api-key", metavar="NAME=VALUE", help="API key, e.g. X-API-Key=abc")
    auth.add_argument("--api-key-in", choices=["header", "query", "cookie"], default="header",
                      help="Where --api-key goes (default: header)")
    auth.add_argument("--header", action="append", metavar="NAME=VALUE",
                      help="Extra request header (repeatable)")
    auth.add_argument("--cookie", action="append", metavar="NAME=VALUE",
                      help="Request cookie (repeatable)")

    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("spec", help="List endpoints")
    s.add_argument("--table", action="store_true", help="Plain-text table instead of JSON")
    s.add_argument("--filter", help="Substring filter on method/path/summary/tag/operationId")
    s.add_argument("--tag", help="Only endpoints with this tag")
    s.add_argument("--method", help="Only endpoints with this HTTP method")
    s.set_defaults(func=cmd_spec)

    w = sub.add_parser("show", help="Show one endpoint's parameters, example body and responses")
    w.add_argument("--method", required=True)
    w.add_argument("--path", required=True, help="Spec path, e.g. /pets/{id}")
    w.set_defaults(func=cmd_show)

    c = sub.add_parser("call", help="Invoke one endpoint")
    c.add_argument("--method", required=True)
    c.add_argument("--path", required=True, help="Spec path, e.g. /pets/{id}")
    c.add_argument("--query", action="append", metavar="NAME=VALUE", help="Query parameter (repeatable)")
    c.add_argument("--path-param", action="append", metavar="NAME=VALUE", help="Path parameter (repeatable)")
    body = c.add_mutually_exclusive_group()
    body.add_argument("--json-body", help="Inline JSON body")
    body.add_argument("--json-file", help="Path to a JSON body file")
    body.add_argument("--body", help="Raw text body (pair with --content-type)")
    body.add_argument("--form", action="append", metavar="NAME=VALUE",
                      help="Form field (repeatable). NAME=@path uploads a file as multipart")
    body.add_argument("--example", action="store_true", help="Build the body from the spec's schema/examples")
    c.add_argument("--content-type", help="Override the request content type")
    c.add_argument("--timeout", type=float, default=30)
    c.add_argument("--raw", action="store_true", help="Print the raw response body only")
    c.add_argument("--full-headers", action="store_true", help="Include all response headers")
    c.add_argument("--output", metavar="FILE", help="Save the response body to a file (works for binary)")
    c.add_argument("--validate", action="store_true",
                   help="Check the response against the spec; a mismatch makes the exit code 1")
    c.add_argument("--curl", action="store_true",
                   help="Print the equivalent curl command (includes credentials) instead of sending")
    c.set_defaults(func=cmd_call)

    l = sub.add_parser("login", help="POST credentials to an auth endpoint and capture a token")
    l.add_argument("--auth-path", required=True, help="Login path or full URL, e.g. /api/token/")
    l.add_argument("--username", required=True, help="Username or email address")
    l.add_argument("--password", help="Password. Visible in shell history and process lists; "
                                      "prefer --password-stdin, $SPECPROBE_PASSWORD or the prompt")
    l.add_argument("--password-stdin", action="store_true", help="Read the password from stdin")
    l.add_argument("--username-field", default="username", help="Body field for the username (default: username)")
    l.add_argument("--password-field", default="password", help="Body field for the password (default: password)")
    l.add_argument("--extra", action="append", metavar="NAME=VALUE",
                   help="Extra body field (repeatable), e.g. --extra tenant=acme")
    l.add_argument("--form", action="store_true",
                   help="Send form-encoded instead of JSON (OAuth2 password grant, FastAPI)")
    l.add_argument("--token-path", help="Dotted path to the token in the response, e.g. result.auth.jwt")
    l.add_argument("--token-only", action="store_true", help="Print only the token string")
    l.add_argument("--timeout", type=float, default=15)
    l.set_defaults(func=cmd_login)

    a = sub.add_parser("audit", help="Call every GET endpoint that needs no invented data")
    a.add_argument("--param", action="append", metavar="NAME=VALUE",
                   help="Value for a parameter on any endpoint (repeatable), e.g. --param version=1")
    a.add_argument("--tag", help="Only endpoints with this tag")
    a.add_argument("--filter", help="Substring filter on path/summary/tag/operationId")
    a.add_argument("--limit", type=int, help="Cap the number of endpoints")
    a.add_argument("--timeout", type=float, default=15)
    a.add_argument("--jobs", type=_positive_int, default=1, metavar="N",
                   help="Requests in flight at once. Default 1; raise it only for servers that can take it")
    a.add_argument("--table", action="store_true", help="Plain-text rows instead of JSON")
    a.add_argument("--validate", action="store_true", help="Also check responses against the spec")
    a.add_argument("--fail-on", choices=sorted(_FAIL_BUCKETS), default="none",
                   help="Exit 1 if any result falls in this class or worse "
                        "(server: 5xx and connection errors; client: plus 4xx; any: plus 401/403). "
                        "With --validate, contract issues count too. Default: none")
    a.set_defaults(func=cmd_audit)

    return p


def _utf8_streams() -> None:
    """API responses can hold any language, and Windows defaults to a legacy code page."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: Optional[list[str]] = None) -> int:
    _utf8_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verbose:
        logging.basicConfig(stream=sys.stderr, format="[specprobe] %(message)s")
        logging.getLogger("specprobe").setLevel(logging.DEBUG)
    if not args.url:
        parser.error("--url is required (or set $SPECPROBE_URL). Global flags go before the subcommand.")
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except UsageError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
