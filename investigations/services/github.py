"""Bounded GitHub source retrieval pinned to a single commit."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .analysis import (
    MAX_FILE_BYTES,
    MAX_GRAPH_BYTES,
    MAX_SOURCE_CHARS_PER_FILE,
    MAX_SOURCE_FILES,
    MAX_SOURCE_LINES,
    MAX_TOTAL_SOURCE_CHARS,
    SUPPORTED_SOURCE_SUFFIXES,
    _graphify_context,
    _redact_sensitive_text,
    _safe_relative_path,
)

GITHUB_API = "https://api.github.com"
MAX_GITHUB_TREE_BYTES = 8_000_000
MAX_GITHUB_TREE_ITEMS = 80_000
MAX_GITHUB_SOURCE_FILES = 8
MAX_GITHUB_REQUEST_SECONDS = 30
MAX_GITHUB_FRAME_PATH = 1_000
REPO_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
GIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
GITHUB_REPO_SEGMENTS = {".git", ".github", "graphify-out", ".venv", "venv", "node_modules", "__pycache__", ".ssh", ".aws", "secrets", "credentials"}
SENSITIVE_REPO_NAME = re.compile(r"(?:^|[._-])(secret|secrets|credential|credentials|password|passwd|api[_-]?key|private[_-]?key)(?:[._-]|$)", re.I)


class InvalidRepository(ValueError):
    """The supplied identifier is not a supported GitHub repository reference."""


class GitHubRepositoryError(Exception):
    """A safe, user-facing repository retrieval failure."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class GitHubContext:
    metadata: dict[str, str]
    sources: list[dict[str, Any]]
    graph_relationships: list[dict[str, str]]
    graphify_status: str
    unresolved_frames: int
    frame_count: int
    graph_source: str
    frame_paths: list[str | None]


def normalize_github_repository(value: str) -> tuple[str, str]:
    """Accept only `owner/repo` or an HTTPS github.com repository URL."""
    if not isinstance(value, str) or len(value) > 512:
        raise InvalidRepository("Enter a GitHub repository as owner/repo or an HTTPS github.com URL.")
    value = value.strip()
    if not value or any(ord(char) < 32 for char in value) or "\\" in value or "%" in value:
        raise InvalidRepository("Enter a valid GitHub repository identifier.")
    if "://" in value:
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise InvalidRepository("Enter a valid GitHub repository URL.") from exc
        if (parsed.scheme.lower() != "https" or parsed.hostname is None
                or parsed.hostname.lower() != "github.com" or parsed.username or parsed.password
                or parsed.port is not None or parsed.query or parsed.fragment):
            raise InvalidRepository("Only HTTPS repository URLs hosted on github.com are supported.")
        segments = parsed.path.strip("/").split("/")
        if len(segments) != 2:
            raise InvalidRepository("Use a repository URL without branch, file, or query components.")
        owner, repo = segments
    else:
        if value.count("/") != 1:
            raise InvalidRepository("Use owner/repo or an HTTPS github.com repository URL.")
        owner, repo = value.split("/", 1)
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if (not REPO_OWNER.fullmatch(owner) or not REPO_NAME.fullmatch(repo)
            or repo in {".", ".."} or repo.startswith("-") or repo.endswith(".")):
        raise InvalidRepository("The GitHub owner or repository name is invalid.")
    return owner, repo


class GitHubAPI:
    """Minimal fixed-host API client; redirects are disabled to protect its token."""

    def __init__(self, token: str = ""):
        self.token = token
        self.deadline = time.monotonic() + MAX_GITHUB_REQUEST_SECONDS
        self.client = httpx.Client(
            timeout=httpx.Timeout(connect=4.0, read=8.0, write=4.0, pool=4.0),
            follow_redirects=False,
        )

    def close(self) -> None:
        self.client.close()

    def get_json(self, route: str, max_bytes: int) -> Any:
        # All routes are constructed from validated path segments by this module.
        url = f"{GITHUB_API}/{route.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "TraceGraph/0.1",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise GitHubRepositoryError("GitHub repository analysis exceeded its time limit.", 504)
            timeout = httpx.Timeout(connect=min(4.0, remaining), read=min(8.0, remaining),
                                     write=min(4.0, remaining), pool=min(4.0, remaining))
            with self.client.stream("GET", url, headers=headers, timeout=timeout) as response:
                if response.status_code != 200:
                    self._raise_http_error(response.status_code, response.headers)
                length = response.headers.get("content-length")
                if length and length.isdecimal() and int(length) > max_bytes:
                    raise GitHubRepositoryError("The GitHub response exceeds TraceGraph's size limit.", 413)
                chunks, received = [], 0
                for chunk in response.iter_bytes():
                    if time.monotonic() >= self.deadline:
                        raise GitHubRepositoryError("GitHub repository analysis exceeded its time limit.", 504)
                    received += len(chunk)
                    if received > max_bytes:
                        raise GitHubRepositoryError("The GitHub response exceeds TraceGraph's size limit.", 413)
                    chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise GitHubRepositoryError("GitHub did not respond before the repository request timed out.", 504) from exc
        except httpx.RequestError as exc:
            raise GitHubRepositoryError("TraceGraph could not connect to GitHub.", 503) from exc
        try:
            return json.loads(b"".join(chunks))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise GitHubRepositoryError("GitHub returned an unusable repository response.", 502) from exc

    def _raise_http_error(self, status: int, headers: Any) -> None:
        if status == 401:
            raise GitHubRepositoryError("GitHub rejected the server-side repository credentials.", 502)
        if status == 403:
            if headers.get("x-ratelimit-remaining") == "0":
                raise GitHubRepositoryError("GitHub's API rate limit was reached.", 429)
            raise GitHubRepositoryError("GitHub denied access to this repository.", 403)
        if status == 404:
            raise GitHubRepositoryError(
                "Repository not found or private. Public repositories work without credentials; private repositories require a server-side GITHUB_TOKEN.",
                404,
            )
        if status == 429:
            raise GitHubRepositoryError("GitHub's API rate limit was reached.", 429)
        if status >= 500:
            raise GitHubRepositoryError("GitHub is temporarily unavailable.", 502)
        raise GitHubRepositoryError("GitHub could not provide this repository.", 502)


def _safe_repo_path(path: str) -> str | None:
    """Validate a repository-relative Python path without accessing local files."""
    if (not isinstance(path, str) or not path or len(path) > MAX_GITHUB_FRAME_PATH
            or "\\" in path or any(ord(char) < 32 for char in path)):
        return None
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {".", ".."} for part in path.split("/")):
        return None
    safe = _safe_relative_path(Path("/tracegraph-remote-root"), path)
    if safe is None:
        return None
    lowered = [part.lower() for part in pure.parts]
    if any(part in GITHUB_REPO_SEGMENTS for part in lowered):
        return None
    if SENSITIVE_REPO_NAME.search(pure.name):
        return None
    return pure.as_posix()


def _normalize_frame_path(frame_path: str, repo_name: str, tree_paths: set[str],
                         basename_index: dict[str, list[str] | None] | None = None) -> str | None:
    if not isinstance(frame_path, str) or len(frame_path) > MAX_GITHUB_FRAME_PATH:
        return None
    windows = PureWindowsPath(frame_path)
    normalized = frame_path.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if ".." in parts:
        return None
    if windows.drive and parts and parts[0].rstrip(":").casefold() == windows.drive.rstrip(":").casefold():
        parts = parts[1:]
    if len(parts) >= 2 and parts[0].casefold() == repo_name.casefold():
        parts = parts[1:]
    candidate = _safe_repo_path("/".join(parts))
    if candidate and candidate in tree_paths:
        return candidate
    if not candidate:
        return None
    if basename_index is None:
        basename_index = {}
        for path in tree_paths:
            name = path.rsplit("/", 1)[-1].casefold()
            values = basename_index.setdefault(name, [])
            if values is not None:
                if len(values) >= 256:
                    basename_index[name] = None
                else:
                    values.append(path)
    # Local traceback roots are machine-specific. Match a unique repository
    # suffix so /workspace/checkouts/project/src/app.py maps to src/app.py.
    for index in range(len(parts)):
        suffix = _safe_repo_path("/".join(parts[index:]))
        if suffix:
            candidates = basename_index.get(suffix.rsplit("/", 1)[-1].casefold(), [])
            if candidates is None:
                return None
            matches = [path for path in candidates if path == suffix or path.endswith("/" + suffix)]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return None
    return None


def _source_excerpt(path: str, line: int, text: str, context: int = 5) -> dict[str, Any] | None:
    if "\x00" in text or len(text.encode("utf-8")) > MAX_FILE_BYTES:
        return None
    lines = text.splitlines()
    if not isinstance(line, int) or line < 1 or line > len(lines):
        return None
    start = max(1, line - context)
    end_limit = min(len(lines), line + context, start + MAX_SOURCE_LINES - 1)
    excerpt_lines, used_chars = [], 0
    end = start - 1
    for number in range(start, end_limit + 1):
        rendered = f"{number}: {lines[number - 1][:1_000]}"
        if used_chars + len(rendered) + 1 > MAX_SOURCE_CHARS_PER_FILE:
            break
        excerpt_lines.append(rendered)
        used_chars += len(rendered) + 1
        end = number
    if end < line:
        return None
    return {"path": path, "start_line": start, "end_line": end, "content": "\n".join(excerpt_lines)}


def _decode_blob(blob: Any, expected_sha: str) -> str | None:
    if not isinstance(blob, dict) or blob.get("encoding") != "base64" or blob.get("sha") != expected_sha:
        return None
    encoded = blob.get("content")
    if not isinstance(encoded, str) or len(encoded) > MAX_FILE_BYTES * 2:
        return None
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True)
        if len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeError, ValueError):
        return None


def _build_graphify_index(source_files: dict[str, str]) -> dict[str, Any] | None:
    """Run Graphify's AST-only updater over bounded source in a temporary tree."""
    executable = shutil.which("graphify")
    if not executable or not source_files:
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="tracegraph-graphify-") as temporary:
            root = Path(temporary).resolve()
            for relative, source in source_files.items():
                safe = _safe_repo_path(relative)
                if not safe:
                    continue
                target = (root / safe).resolve()
                target.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            env = {"PATH": os.pathsep.join((str(Path(executable).parent), os.defpath, "/usr/local/bin")),
                   "HOME": temporary, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
            result = subprocess.run(
                [executable, "update", str(root), "--no-cluster"],
                cwd=root, env=env, capture_output=True, timeout=8, check=False,
            )
            graph_path = (root / "graphify-out" / "graph.json").resolve()
            graph_path.relative_to(root)
            if result.returncode != 0 or not graph_path.is_file() or graph_path.stat().st_size > MAX_GRAPH_BYTES:
                return None
            data = json.loads(graph_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
    except (OSError, UnicodeError, ValueError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError, RecursionError):
        return None


def retrieve_github_context(repository: str, frames: list[dict[str, Any]], *, token: str = "") -> GitHubContext:
    """Resolve repository default branch to a SHA, then retrieve only traceback source files."""
    owner, repo = normalize_github_repository(repository)
    api = GitHubAPI(token)
    try:
        repository_data = api.get_json(f"repos/{quote(owner, safe='')}/{quote(repo, safe='')}", 256_000)
        if not isinstance(repository_data, dict) or not isinstance(repository_data.get("default_branch"), str):
            raise GitHubRepositoryError("GitHub returned incomplete repository metadata.", 502)
        default_branch = repository_data["default_branch"]
        commit_data = api.get_json(
            f"repos/{quote(owner, safe='')}/{quote(repo, safe='')}/commits/{quote(default_branch, safe='')}",
            512_000,
        )
        commit_sha = commit_data.get("sha") if isinstance(commit_data, dict) else None
        if not isinstance(commit_sha, str) or not GIT_SHA.fullmatch(commit_sha):
            raise GitHubRepositoryError("GitHub did not return a valid commit revision.", 502)
        tree = api.get_json(
            f"repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/trees/{commit_sha}?recursive=1",
            MAX_GITHUB_TREE_BYTES,
        )
        entries = tree.get("tree") if isinstance(tree, dict) else None
        if not isinstance(entries, list) or tree.get("truncated") is True or len(entries) > MAX_GITHUB_TREE_ITEMS:
            raise GitHubRepositoryError("This repository's source tree is too large to analyze safely.", 413)
        tree_files: dict[str, str] = {}
        graph_sha = None
        for item in entries:
            if not isinstance(item, dict) or item.get("type") != "blob" or item.get("mode") == "120000":
                continue
            if item.get("path") == "graphify-out/graph.json":
                candidate_sha, candidate_size = item.get("sha"), item.get("size")
                if (isinstance(candidate_sha, str) and GIT_SHA.fullmatch(candidate_sha)
                        and type(candidate_size) is int and candidate_size <= MAX_GRAPH_BYTES):
                    graph_sha = candidate_sha
                continue
            path = _safe_repo_path(item.get("path"))
            sha = item.get("sha")
            size = item.get("size")
            if (path and path not in tree_files and isinstance(sha, str) and GIT_SHA.fullmatch(sha)
                    and type(size) is int and 0 <= size <= MAX_FILE_BYTES):
                tree_files[path] = sha
        basename_index: dict[str, list[str] | None] = {}
        for path in tree_files:
            name = path.rsplit("/", 1)[-1].casefold()
            candidates = basename_index.setdefault(name, [])
            if candidates is not None:
                if len(candidates) >= 256:
                    basename_index[name] = None
                else:
                    candidates.append(path)
        tree_path_set = set(tree_files)
        mapped: list[tuple[str, int] | None] = []
        unresolved = 0
        repo_name = repository_data.get("name") if isinstance(repository_data.get("name"), str) else repo
        for frame in frames:
            path = _normalize_frame_path(frame["path"], repo_name, tree_path_set, basename_index)
            if not path:
                unresolved += 1
                mapped.append(None)
            else:
                mapped.append((path, frame["line"]))
        resolved_mapped = [item for item in mapped if item]
        unique_paths = list(dict.fromkeys(path for path, _ in resolved_mapped))[:MAX_GITHUB_SOURCE_FILES]
        source_files: dict[str, str] = {}
        for path in unique_paths:
            try:
                blob = api.get_json(
                    f"repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/blobs/{tree_files[path]}",
                    MAX_FILE_BYTES * 2,
                )
            except GitHubRepositoryError:
                unresolved += sum(mapped_path == path for item in resolved_mapped if item for mapped_path, _ in [item])
                continue
            text = _decode_blob(blob, tree_files[path])
            if text is None:
                unresolved += sum(mapped_path == path for item in resolved_mapped if item for mapped_path, _ in [item])
            else:
                source_files[path] = text
        if len(unique_paths) < len({path for path, _ in resolved_mapped}):
            unresolved += len({path for path, _ in resolved_mapped}) - len(unique_paths)

        sources: list[dict[str, Any]] = []
        source_chars = 0
        for item in resolved_mapped:
            path, line = item
            text = source_files.get(path)
            excerpt = _source_excerpt(path, line, text) if text is not None else None
            if not excerpt:
                unresolved += 1
                continue
            if source_chars + len(excerpt["content"]) > MAX_TOTAL_SOURCE_CHARS:
                unresolved += 1
                continue
            sources.append(excerpt)
            source_chars += len(excerpt["content"])
            if len(sources) >= MAX_SOURCE_FILES:
                break

        graph_data = None
        if graph_sha:
            try:
                graph_blob = api.get_json(
                    f"repos/{quote(owner, safe='')}/{quote(repo, safe='')}/git/blobs/{graph_sha}",
                    MAX_GRAPH_BYTES * 2,
                )
                graph_text = _decode_graph_blob(graph_blob, graph_sha)
                graph_data = json.loads(graph_text) if graph_text else None
            except (GitHubRepositoryError, json.JSONDecodeError, RecursionError):
                graph_data = None
        graph_source = "committed_index" if isinstance(graph_data, dict) else "source_fallback"
        if not isinstance(graph_data, dict):
            graph_data = _build_graphify_index(source_files)
            graph_source = "generated_index" if isinstance(graph_data, dict) else "source_fallback"
        relationships, graph_status = _graphify_context(frames, sources, graph_data=graph_data or {})
        full_name = repository_data.get("full_name")
        if not isinstance(full_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name):
            full_name = f"{owner}/{repo}"
        metadata = {
            "full_name": full_name,
            "url": f"https://github.com/{owner}/{repo}",
            "commit_sha": commit_sha,
        }
        return GitHubContext(metadata, sources, relationships, graph_status, min(unresolved, len(frames)),
                             len(frames), graph_source, [item[0] if item else None for item in mapped])
    finally:
        api.close()


def _decode_graph_blob(blob: Any, expected_sha: str) -> str | None:
    if not isinstance(blob, dict) or blob.get("encoding") != "base64" or blob.get("sha") != expected_sha:
        return None
    encoded = blob.get("content")
    if not isinstance(encoded, str) or len(encoded) > MAX_GRAPH_BYTES * 2:
        return None
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True)
        if len(raw) > MAX_GRAPH_BYTES or b"\x00" in raw:
            return None
        return raw.decode("utf-8", errors="strict")
    except (binascii.Error, UnicodeError, ValueError):
        return None
