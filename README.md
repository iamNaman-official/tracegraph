# TraceGraph

TraceGraph is a Django debugging assistant. It parses formatted Python tracebacks, safely retrieves relevant source from this project, optionally adds context from an existing Graphify index, and asks the configured Gemma model for a diagnosis. It does not persist submitted tracebacks.

## Setup and configuration

Python 3.13+ is required. Install the locked dependencies with `uv sync`. SQLite is the default. PostgreSQL can be selected with `DATABASE_URL` or the `POSTGRES_*` variables below. Database configuration is independent from the source repository root used for evidence lookup.

Configuration is read from the process environment. The existing dotenv loader will also load a local `.env` for Django runtime configuration; never commit that file.

| Variable | Purpose | Default |
| --- | --- | --- |
| `DJANGO_SECRET_KEY` | Django signing/session secret; set to a private random value in production | Random process-local value in `DEBUG` development; required when `DJANGO_DEBUG=False` |
| `DJANGO_DEBUG` | Django debug mode | `False`; set `True` for local development |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated host names | `localhost,127.0.0.1` |
| `GEMINI_API_KEY` | Google GenAI key (`GOOGLE_API_KEY` is accepted as a fallback) | Empty; analysis returns a limited fallback |
| `GEMINI_MODEL` | Google GenAI model name | `gemma-4-26b-a4b-it` |
| `TRACEGRAPH_REPOSITORY_ROOT` | Local repository root for source and Graphify lookup | Django project directory |
| `GITHUB_TOKEN` | Optional server-side token for repositories the token can access | Empty; public repositories work without it |
| `DATABASE_URL` | PostgreSQL connection URL; takes precedence over `POSTGRES_*` | Unset; SQLite is used |
| `POSTGRES_DB` | PostgreSQL database name; activates PostgreSQL when set | Unset |
| `POSTGRES_USER` | PostgreSQL user | Empty |
| `POSTGRES_PASSWORD` | PostgreSQL password | Empty |
| `POSTGRES_HOST` | PostgreSQL host | `localhost` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `POSTGRES_SSLMODE` | Optional libpq SSL mode | Unset |

`DATABASE_URL` supports `postgres://`, `postgresql://`, and `postgresql+psycopg://` URLs. Query options are limited to `sslmode`, `connect_timeout`, `application_name`, and `target_session_attrs`. Invalid database configuration fails during settings loading rather than silently falling back to SQLite. Do not put database URLs or passwords in source control.

Start the local server in development mode with:

```sh
DJANGO_DEBUG=True uv run python manage.py runserver
```

Open <http://127.0.0.1:8000/> and paste a full Python traceback. Leave GitHub repository blank to analyze the configured local project, or enter `owner/repo` / an HTTPS `github.com` repository URL to analyze a selected repository. The page shows an immediate spinner, an indeterminate progress bar, and the ordered server workflow while the single request is in flight. It does not claim individual server stages have completed before a response arrives. The request has a 45-second browser timeout, and the loading state clears on every result or error. Use “New investigation” to reset the editor and report. A fallback diagnosis is explicitly labeled when Gemma is not configured or unavailable.

## API contract

`POST /api/investigations/analyze/` accepts `Content-Type: application/json` and a non-empty Python traceback. The optional `repository` field selects a GitHub source tree:

```json
{
  "traceback": "Traceback (most recent call last):\n  File \"app.py\", line 12, in run\nValueError: invalid input",
  "repository": "owner/repo"
}
```

When `repository` is provided, the response adds `repository` with `full_name`, canonical HTTPS `url`, pinned `commit_sha`, `graphify_source` (`committed_index`, `generated_index`, or `source_fallback`), and `unresolved_frames`. The SHA is resolved before source retrieval; source blobs and a committed `graphify-out/graph.json` are read from that immutable revision. Local absolute traceback paths are treated as path hints and mapped to a unique repository-relative suffix; they are never read from the TraceGraph server. Ambiguous or missing paths remain unresolved. Analysis retrieves at most eight files matched by traceback frames, each at most 128 KB, and limits the recursive tree response to 8 MB / 80,000 entries. It never executes repository code. GitHub content is not cached; temporary Graphify work is removed after each request.

Only `https://github.com/owner/repo` and `owner/repo` are accepted. Public repositories need no token. A server-side `GITHUB_TOKEN` may grant access to private repositories; credentials supplied in request JSON are rejected, and the token is never included in the model prompt or returned. Repository URLs cannot select alternate hosts or arbitrary paths. GitHub errors are returned as safe JSON messages. Source and Graphify retrieval share the same pinned revision. If a readable committed graph index exists it is used; otherwise, when the `graphify` command is installed, TraceGraph may build a short-lived AST-only index from the bounded retrieved files; if unavailable or unusable, source excerpts remain the fallback. The generated graph represents only the retrieved subset, not the entire repository.

Successful model analysis returns HTTP 200 and the stable schema below. The diagnosis fields describe the result. `hypotheses` are model-generated possibilities; `exception_type` and `traceback_facts` are parsed from traceback text; `source_facts` identify retrieved excerpts; `graph_relationships` contains relevant Graphify edges labeled `extracted`, `inferred`, or `unspecified`; and `graphify_status` reports `used`, `available_no_matches`, or `unavailable`. `evidence` is limited to model citations whose repository-relative paths and absolute source line ranges were validated against retrieved files.

```json
{
  "diagnosis_mode": "gemma",
  "summary": "Short diagnosis summary",
  "likely_cause": "The most likely cause",
  "evidence": [{
    "source_path": "app.py",
    "start_line": 12,
    "end_line": 12,
    "explanation": "Why these source lines support the diagnosis"
  }],
  "hypotheses": ["A possible alternative explanation"],
  "recommended_steps": ["A concrete debugging step"],
  "limitations": [],
  "traceback_facts": [{"source_path": "app.py", "line": 12, "function": "run"}],
  "source_facts": [{"source_path": "app.py", "start_line": 7, "end_line": 17}],
  "graph_relationships": [{"from": "run", "relationship": "calls", "to": "helper", "evidence_type": "extracted"}],
  "graphify_status": "used",
  "exception_type": "ValueError"
}
```

When the key is missing or the model times out, reaches quota limits, fails, or returns malformed data, the endpoint returns a useful fallback report with `diagnosis_mode: "fallback"`; it never claims Gemma ran. Missing credentials return HTTP 503, timeout 504, quota/rate limit 429, and malformed or upstream errors 502. Browser users still see the fallback report and its safe status message. Invalid JSON/traceback input returns HTTP 400, an unsupported media type returns HTTP 415, an oversized request body returns HTTP 413, and other methods return HTTP 405.

## CSRF and Bruno

CSRF protection remains enabled. The browser loads `/`, receives Django's `csrftoken` cookie, and reads the rendered `csrfmiddlewaretoken` from the page. Its same-origin JSON request sends both the cookie and `X-CSRFToken` header. There is no CSRF exemption on the API.

For Bruno using the default session-based CSRF design:

1. Send `GET http://127.0.0.1:8000/` first with Bruno's cookie jar enabled. Keep the returned `csrftoken` cookie.
2. Copy the `value` from the page's hidden `csrfmiddlewaretoken` input into a Bruno variable such as `csrfToken` (the token and cookie are not secrets, but should still be handled as session request data).
3. Send `POST http://127.0.0.1:8000/api/investigations/analyze/` with `Content-Type: application/json`, `X-CSRFToken: {{csrfToken}}`, and the JSON request body above. Send the cookie jar's `csrftoken` cookie with the request.

Missing or invalid CSRF tokens receive HTTP 403. This protects session-authenticated browser clients; a server-to-server client should use an intentional authentication design rather than disabling CSRF globally.

## Source and model security

Source retrieval resolves paths against the configured project root and rejects traversal, escaping symlinks, secret/credential files, virtual environments, dependency folders, unsupported file types, and oversized files. It returns at most 12 Python snippets, capped at 10,000 characters each and 60,000 characters total. Common credential assignment patterns and well-known token formats are redacted before sending context to Gemma. Submitted traceback details and retrieved excerpts are sent to Google when a model key is configured. Avoid submitting data you are not permitted to send to that service. Model output is treated as untrusted: citations must refer to retrieved source files and valid line ranges before they are returned.

For local analysis, Graphify context is used only when a readable, bounded `graphify-out/graph.json` is present and contains `nodes` plus `links`, `edges`, or `relationships`. Node paths may be stored as `source_file`; link endpoints support `source`/`target` and common aliases, and relationship labels include Graphify's `relation` field. Extracted and inferred provenance is retained. Hyperedges are used only when they provide an explicit endpoint pair; opaque member sets are not flattened into invented pairwise relationships. Missing, malformed, oversized, or escaping-symlink indexes, and valid indexes without relevant matches, are reported separately; source retrieval remains available.

Set `TRACEGRAPH_REPOSITORY_ROOT` when Django runs separately from the source checkout. Source retrieval and Graphify lookup resolve against that same root and reject traversal and escaping symlinks.

DuckDB is not integrated into the analysis data flow. The current Graphify index is a small per-request context file, so there is no useful analytical workload to justify a second query engine; Django's application database remains SQLite by default or PostgreSQL when configured. In the current environment, `pg_isready` reports no response from the local default PostgreSQL socket, so PostgreSQL connectivity and migrations were not verified.

## Checks and tests

```sh
DJANGO_DEBUG=True uv run python manage.py check
DJANGO_DEBUG=True uv run python manage.py test
```

Tests mock Google GenAI responses. They do not verify live Gemma inference.
