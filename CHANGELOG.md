# Changelog

## 1.0.0

First public release. The project is now an installable package (`specprobe/`) with `specprobe` and `specprobe-gui` commands, and the Qt dependency is optional.

### Added

- Auth: API keys (header, query or cookie), HTTP Basic, custom token schemes and cookie sessions, preselected from the spec's security schemes.
- Login: form-encoded and OAuth2 password grant, configurable password field, token path, tokens in response headers, and login endpoints suggested from the spec.
- Bodies: urlencoded forms, multipart file uploads, raw text, and a choice of the spec's content types.
- Contract checks: response status and schema validation in the GUI, `call --validate` and `audit --validate`.
- Audit in the GUI, plus `audit --param` and `audit --fail-on` for CI. Skipped endpoints are now reported.
- Local spec files. Spec discovery that reads docs pages and init scripts, and specs behind authentication.
- GUI: server picker, per-API settings, drafts kept across endpoints, request history, Docs tab, extra headers, enum dropdowns, cancel, timeout, Copy as cURL, Save response, Log tab, and dark theme support.
- CLI: `show` subcommand, `--curl`, `--output`, `--form`, `--body`, `--version`, `$SPECPROBE_URL`, and safer ways to supply a password.
- Test suite running against a local mock API.

### Changed

- **TLS verification is on by default in the GUI.**
- **Tokens are no longer saved automatically.** Saving is opt-in per API, and a token stored by an earlier version is deleted on first launch.
- Removed every backend-specific default: the prefilled URL, the `version=1` guess and the shared global login values.
- `login()` now returns a `LoginResult` instead of a tuple.
- The CLI is quiet by default. Use `-v` for the request trace.
- `cli.bat` no longer changes directory, so relative paths work.

### Fixed

- A pasted spec URL was never tried directly unless it ended in `.json` or `.yaml`.
- Any JSON object was accepted as a spec.
- `$ref` parameters and request bodies were dropped, and operation parameters didn't override path-level ones.
- Swagger 2.0: `basePath` was lost without a `host`, and inline defaults and `formData` parameters were ignored.
- Relative `servers` and server variables were resolved incorrectly.
- Path values weren't percent-encoded, and repeated `--query` flags kept only the last value.
- Header and cookie parameters weren't sent in some flows, and array parameters ignored their declared format.
- `--filter` was ignored in JSON output, and non-ASCII output could crash on Windows.
- Closing a dialog or the window during a request could crash the app.
- Text from servers and specs could be rendered as HTML in the GUI.
- Secrets in query strings could reach logs and error messages.
- JSON highlighting miscoloured string values.
- Responses that don't name a charset are decoded as UTF-8 instead of being guessed. Guessing took seconds on binary or large bodies.
- With PySide6 6.12, closing the window could crash, with or without a request in progress.
- In dark mode on Windows, unticked checkboxes were drawn as solid navy boxes.
- With several specs listed (springdoc groups), an empty first group was loaded, showing no endpoints. `urls.primaryName` is now honoured.
