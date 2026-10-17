import json
import re
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse

from investigations.services.analysis import InvalidTraceback, _exception_details, _graphify_context, _upstream_failure, parse_traceback, retrieve_source
from investigations.services.github import InvalidRepository, _normalize_frame_path, normalize_github_repository, retrieve_github_context


class TracebackParsingTests(SimpleTestCase):
    def test_parses_python_traceback_frames(self):
        frames = parse_traceback('Traceback (most recent call last):\n  File "app.py", line 12, in run\nValueError: bad')
        self.assertEqual(frames, [{"path": "app.py", "line": 12, "function": "run"}])

    def test_rejects_empty_or_non_python_input(self):
        for value in ("", "ordinary text", 12):
            with self.subTest(value=value), self.assertRaises(InvalidTraceback):
                parse_traceback(value)

    def test_extracts_exception_type_and_message(self):
        self.assertEqual(_exception_details("Traceback (most recent call last):\n  File 'app.py', line 1, in run\nValueError: broken input"),
                         ("ValueError", "broken input"))


class GitHubRepositoryTests(SimpleTestCase):
    def test_repository_normalization_only_accepts_github_https_or_owner_repo(self):
        self.assertEqual(normalize_github_repository("octo/project"), ("octo", "project"))
        self.assertEqual(normalize_github_repository("https://github.com/octo/project.git"), ("octo", "project"))
        for value in ("http://github.com/octo/project", "https://evil.example/octo/project", "octo/../project",
                      "https://github.com/octo/project/tree/main", "https://user:pw@github.com/octo/project"):
            with self.subTest(value=value), self.assertRaises(InvalidRepository):
                normalize_github_repository(value)

    def test_local_absolute_and_relative_traceback_paths_match_repo_tree(self):
        paths = {"src/app.py"}
        for value in ("project/src/app.py", "./src/app.py", "/workspace/project/src/app.py", r"C:\workspace\project\src\app.py"):
            self.assertEqual(_normalize_frame_path(value, "project", paths), "src/app.py")
        self.assertIsNone(_normalize_frame_path("../../secrets.py", "project", paths))

    def test_retrieval_pins_tree_blobs_and_graph_to_resolved_sha(self):
        from investigations.services import github

        commit = "a" * 40
        source = "def handler():\n    raise ValueError('bad')\n"
        graph = json.dumps({
            "nodes": [{"id": "handler", "label": "handler", "source_file": "src/app.py", "source_location": "L1"},
                      {"id": "helper", "label": "helper", "source_file": "src/helper.py", "source_location": "L1"}],
            "links": [{"source": "handler", "target": "helper", "relation": "calls", "_origin": "ast"}],
            "hyperedges": [],
        })
        source_sha, graph_sha = "b" * 40, "c" * 40
        class FakeAPI:
            def __init__(self, token=""):
                self.token = token
            def close(self):
                pass
            def get_json(self, route, max_bytes):
                if route == "repos/octo/project":
                    return {"name": "project", "full_name": "octo/project", "default_branch": "main"}
                if route.endswith("/commits/main"):
                    return {"sha": commit}
                if route.endswith(f"/git/trees/{commit}?recursive=1"):
                    return {"truncated": False, "tree": [
                        {"path": "src/app.py", "type": "blob", "sha": source_sha, "size": len(source)},
                        {"path": "graphify-out/graph.json", "type": "blob", "sha": graph_sha, "size": len(graph)},
                        {"path": ".env", "type": "blob", "sha": "d" * 40, "size": 10},
                    ]}
                sha = route.rsplit("/", 1)[-1]
                text = source if sha == source_sha else graph
                return {"sha": sha, "encoding": "base64", "content": __import__("base64").b64encode(text.encode()).decode()}
        requested = []
        original = FakeAPI.get_json
        def recording(self, route, max_bytes):
            requested.append(route)
            return original(self, route, max_bytes)
        with patch.object(github, "GitHubAPI", FakeAPI), patch.object(FakeAPI, "get_json", recording):
            result = retrieve_github_context("octo/project", [{"path": "/build/project/src/app.py", "line": 2, "function": "handler"}], token="server-secret")
        self.assertEqual(result.metadata["commit_sha"], commit)
        self.assertEqual(result.sources[0]["path"], "src/app.py")
        self.assertEqual(result.frame_paths, ["src/app.py"])
        self.assertEqual(result.graphify_status, "used")
        self.assertEqual(result.graph_relationships[0]["relationship"], "calls")
        self.assertTrue(any(f"/git/trees/{commit}?recursive=1" in route for route in requested))
        self.assertFalse(any(".env" in route for route in requested))
        self.assertFalse(any("server-secret" in route for route in requested))

    def test_missing_graphify_uses_safe_source_fallback(self):
        from investigations.services import github
        with patch.object(github, "GitHubAPI") as api_cls, patch.object(github, "_build_graphify_index", return_value=None):
            api = api_cls.return_value
            api.get_json.side_effect = [
                {"name": "project", "full_name": "octo/project", "default_branch": "main"},
                {"sha": "a" * 40},
                {"truncated": False, "tree": [{"path": "app.py", "type": "blob", "sha": "b" * 40, "size": 30}]},
                {"sha": "b" * 40, "encoding": "base64", "content": __import__("base64").b64encode(b"x = 1\n").decode()},
            ]
            result = retrieve_github_context("octo/project", [{"path": "project/app.py", "line": 1, "function": "run"}])
        self.assertEqual(result.graph_source, "source_fallback")
        self.assertEqual(result.graphify_status, "unavailable")
        api.close.assert_called_once()


class SafeSourceRetrievalTests(SimpleTestCase):
    def test_reads_source_and_bounds_excerpt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("a\nb\nc\nd\ne\n", encoding="utf-8")
            result = retrieve_source("app.py", 3, root=root, context=1)
        self.assertEqual((result["start_line"], result["end_line"]), (2, 4))
        self.assertIn("3: c", result["content"])

    def test_rejects_traversal_symlinks_secrets_missing_files_and_bad_lines(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            outside_file = Path(outside) / "secret.txt"
            outside_file.write_text("do not read", encoding="utf-8")
            (root / "link.py").symlink_to(outside_file)
            (root / ".env").write_text("hidden", encoding="utf-8")
            (root / "secret-notes.txt").write_text("hidden too", encoding="utf-8")
            (root / "app.py").write_text("one line\n", encoding="utf-8")
            (root / "notes.txt").write_text("not source\n", encoding="utf-8")
            self.assertIsNone(retrieve_source("../secret.txt", 1, root=root))
            self.assertIsNone(retrieve_source("link.py", 1, root=root))
            self.assertIsNone(retrieve_source(".env", 1, root=root))
            self.assertIsNone(retrieve_source("secret-notes.txt", 1, root=root))
            self.assertIsNone(retrieve_source("missing.py", 1, root=root))
            self.assertIsNone(retrieve_source("app.py", 2, root=root))
            self.assertIsNone(retrieve_source("notes.txt", 1, root=root))

    def test_source_excerpt_is_bounded_and_python_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "large.py").write_text("x" * 20_000 + "\n", encoding="utf-8")
            excerpt = retrieve_source("large.py", 1, root=root)
            self.assertLessEqual(len(excerpt["content"]), 1_010)


class GraphifyTests(SimpleTestCase):
    def test_extracts_relevant_relationships_and_marks_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("def handler(): pass\n", encoding="utf-8")
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(json.dumps({
                "nodes": [{"id": "handler", "name": "handler", "file": "app.py"},
                          {"id": "helper", "name": "helper", "file": "util.py"}],
                "edges": [{"source": "handler", "target": "helper", "type": "calls", "provenance": "extracted"},
                          {"source": "handler", "target": "helper", "type": "may_call", "inferred": True}],
            }), encoding="utf-8")
            frames = [{"path": str(root / "app.py"), "line": 1, "function": "handler"}]
            sources = [{"path": "app.py", "start_line": 1, "end_line": 1, "content": "1: def handler(): pass"}]
            with override_settings(BASE_DIR=root):
                relationships, status = _graphify_context(frames, sources)
        self.assertEqual(status, "used")
        self.assertEqual([edge["evidence_type"] for edge in relationships], ["extracted", "inferred"])
        self.assertEqual(relationships[0]["relationship"], "calls")

    def test_graphify_real_links_schema_matches_source_file_and_endpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("def handler(): pass\n", encoding="utf-8")
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(json.dumps({
                "nodes": [{"id": "node-handler", "label": "handler()", "source_file": "app.py", "source_location": "L1"},
                          {"id": "node-other", "label": "other()", "source_file": "app.py", "source_location": "L20"},
                          {"id": "node-helper", "label": "helper", "source_file": "util.py", "source_location": "L7"}],
                "links": [{"source": "node-handler", "target": "node-helper", "relation": "calls",
                           "_origin": "ast", "confidence": "EXTRACTED", "source_file": "app.py", "source_location": "L1"},
                          {"source": "node-other", "target": "node-helper", "relation": "unrelated_call",
                           "_origin": "ast", "confidence": "EXTRACTED"}],
                "hyperedges": [],
            }), encoding="utf-8")
            frames = [{"path": str(root / "app.py"), "line": 1, "function": "handler"}]
            sources = [{"path": "app.py", "start_line": 1, "end_line": 1, "content": "1: def handler(): pass"}]
            with override_settings(BASE_DIR=root, TRACEGRAPH_REPOSITORY_ROOT=None):
                relationships, status = _graphify_context(frames, sources)
        self.assertEqual(status, "used")
        self.assertEqual(relationships, [{"from": "handler()", "relationship": "calls", "to": "helper", "evidence_type": "extracted"}])

    def test_explicit_hyperedge_endpoints_are_supported_without_flattening_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(json.dumps({
                "nodes": [{"id": "a", "label": "handler", "source_file": "app.py"},
                          {"id": "b", "label": "dependency", "source_file": "dep.py"}],
                "links": [],
                "hyperedges": [{"source": "a", "target": "b", "relation": "jointly_uses", "confidence": "EXTRACTED"}],
            }), encoding="utf-8")
            frames = [{"path": str(root / "app.py"), "line": 1, "function": "handler"}]
            with override_settings(BASE_DIR=root, TRACEGRAPH_REPOSITORY_ROOT=None):
                relationships, status = _graphify_context(frames, [])
        self.assertEqual(status, "used")
        self.assertEqual(relationships[0]["relationship"], "jointly_uses")
        self.assertEqual(relationships[0]["evidence_type"], "extracted")

    def test_valid_graph_without_relevant_matches_reports_no_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(json.dumps({"nodes": [{"id": "x", "label": "elsewhere", "source_file": "other.py"}],
                                        "links": [], "hyperedges": []}), encoding="utf-8")
            with override_settings(BASE_DIR=root, TRACEGRAPH_REPOSITORY_ROOT=None):
                relationships, status = _graphify_context([{"path": "app.py", "line": 1, "function": "run"}], [])
        self.assertEqual(relationships, [])
        self.assertEqual(status, "available_no_matches")

    def test_oversized_graph_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(" " * 128, encoding="utf-8")
            with override_settings(BASE_DIR=root, TRACEGRAPH_REPOSITORY_ROOT=None), patch("investigations.services.analysis.MAX_GRAPH_BYTES", 64):
                relationships, status = _graphify_context([], [])
        self.assertEqual((relationships, status), ([], "unavailable"))

    def test_configured_repository_root_is_shared_by_source_and_graph_lookup(self):
        with tempfile.TemporaryDirectory() as app_dir, tempfile.TemporaryDirectory() as repository_dir:
            root = Path(repository_dir)
            (root / "app.py").write_text("def handler(): pass\n", encoding="utf-8")
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(json.dumps({"nodes": [{"id": "h", "label": "handler", "source_file": "app.py"},
                                                    {"id": "u", "label": "util", "source_file": "util.py"}],
                                        "links": [{"source": "h", "target": "u", "relation": "calls"}],
                                        "hyperedges": []}), encoding="utf-8")
            with override_settings(BASE_DIR=Path(app_dir), TRACEGRAPH_REPOSITORY_ROOT=root):
                source = retrieve_source("app.py", 1)
                relationships, status = _graphify_context(
                    [{"path": "app.py", "line": 1, "function": "handler"}], [source])
        self.assertIsNotNone(source)
        self.assertEqual(status, "used")
        self.assertEqual(relationships[0]["relationship"], "calls")

    def test_invalid_or_missing_graph_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            with tempfile.TemporaryDirectory() as outside:
                outside_graph = Path(outside) / "graph.json"
                outside_graph.write_text(json.dumps({"nodes": [], "edges": []}), encoding="utf-8")
                root = Path(directory)
                graph = root / "graphify-out" / "graph.json"
                graph.parent.mkdir()
                graph.symlink_to(outside_graph)
                with override_settings(BASE_DIR=root):
                    escaped_relationships, escaped_status = _graphify_context([], [])
            root = Path(directory)
            frames, sources = [], []
            with override_settings(BASE_DIR=root):
                relationships, status = _graphify_context(frames, sources)
                graph = root / "graphify-out" / "graph.json"
                graph.unlink()
                graph.write_text("not json", encoding="utf-8")
                invalid_relationships, invalid_status = _graphify_context(frames, sources)
        self.assertEqual((relationships, status), ([], "unavailable"))
        self.assertEqual((invalid_relationships, invalid_status), ([], "unavailable"))
        self.assertEqual((escaped_relationships, escaped_status), ([], "unavailable"))

    def test_graph_item_count_overflow_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graph = root / "graphify-out" / "graph.json"
            graph.parent.mkdir()
            graph.write_text(json.dumps({"nodes": [], "links": [{"source": "a", "target": "b", "relation": "calls"}],
                                         "hyperedges": []}), encoding="utf-8")
            with override_settings(BASE_DIR=root, TRACEGRAPH_REPOSITORY_ROOT=None), patch("investigations.services.analysis.MAX_GRAPH_ITEMS", 0):
                relationships, status = _graphify_context([], [])
        self.assertEqual((relationships, status), ([], "unavailable"))


@override_settings(ROOT_URLCONF="config.urls")
class AnalyzeEndpointTests(SimpleTestCase):
    def setUp(self):
        self.client = Client()
        self.url = reverse("analyze-investigation")

    def test_invalid_input_returns_400(self):
        response = self.client.post(self.url, data="{", content_type="application/json")
        self.assertEqual(response.status_code, 400)
        response = self.client.post(self.url, data=json.dumps({"traceback": "no traceback"}), content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_repository_input_validation_and_user_tokens_are_rejected(self):
        traceback = 'Traceback (most recent call last):\n  File "app.py", line 1, in fail\nRuntimeError: broken'
        for body in ({"traceback": traceback, "repository": "https://example.org/owner/repo"},
                     {"traceback": traceback, "repository": "owner/repo", "github_token": "do-not-accept"}):
            response = self.client.post(self.url, data=json.dumps(body), content_type="application/json")
            self.assertEqual(response.status_code, 400)

    @override_settings(GEMINI_API_KEY="test-key", GITHUB_TOKEN="server-only-token", BASE_DIR=Path("/tmp/tracegraph-api-error"))
    def test_repository_endpoint_returns_pinned_revision_and_uses_mapped_source(self):
        from investigations.services.github import GitHubContext
        traceback = 'Traceback (most recent call last):\n  File "/build/project/src/app.py", line 2, in handler\nRuntimeError: broken'
        context = GitHubContext(
            metadata={"full_name": "octo/project", "url": "https://github.com/octo/project", "commit_sha": "a" * 40},
            sources=[{"path": "src/app.py", "start_line": 1, "end_line": 3, "content": "1: def handler():\\n2: raise RuntimeError()\\n3: pass"}],
            graph_relationships=[{"from": "handler", "relationship": "calls", "to": "helper", "evidence_type": "extracted"}],
            graphify_status="used", unresolved_frames=0, frame_count=1, graph_source="committed_index", frame_paths=["src/app.py"],
        )
        model_payload = {"summary": "A failure", "likely_cause": "Raised at the failing line", "evidence": [
            {"source_path": "src/app.py", "start_line": 2, "end_line": 2, "explanation": "The frame raises here."}],
            "hypotheses": [], "recommended_steps": ["Check the caller"], "limitations": []}
        with (patch("investigations.services.github.retrieve_github_context", return_value=context) as retrieve,
              patch("google.genai.Client") as client_class):
            client_class.return_value.models.generate_content.return_value = Mock(text=json.dumps(model_payload))
            response = self.client.post(self.url, data=json.dumps({"traceback": traceback, "repository": "octo/project"}),
                                        content_type="application/json")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["repository"]["commit_sha"], "a" * 40)
        self.assertEqual(body["repository"]["graphify_source"], "committed_index")
        self.assertEqual(body["evidence"][0]["source_path"], "src/app.py")
        retrieve.assert_called_once()
        self.assertEqual(retrieve.call_args.kwargs["token"], "server-only-token")
        prompt = client_class.return_value.models.generate_content.call_args.kwargs["contents"]
        self.assertNotIn("server-only-token", prompt)
        self.assertNotIn("/build/project", prompt)
        self.assertIn("octo/project", prompt)

    def test_github_retrieval_errors_return_safe_status(self):
        from investigations.services.github import GitHubRepositoryError
        with patch("investigations.services.github.retrieve_github_context", side_effect=GitHubRepositoryError("Repository not found or private.", 404)):
            traceback = 'Traceback (most recent call last):\n  File "app.py", line 1, in fail\nRuntimeError: broken'
            response = self.client.post(self.url, data=json.dumps({"traceback": traceback, "repository": "owner/repo"}), content_type="application/json")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"error": "Repository not found or private."})

    def test_unsupported_content_type_method_and_oversized_body(self):
        self.assertEqual(self.client.post(self.url, data="traceback", content_type="text/plain").status_code, 415)
        self.assertEqual(self.client.get(self.url).status_code, 405)
        oversized = json.dumps({"traceback": "x" * 360_000})
        self.assertEqual(self.client.post(self.url, data=oversized, content_type="application/json").status_code, 413)

    @override_settings(GEMINI_API_KEY="")
    def test_browser_page_posts_with_csrf_and_rejects_missing_token(self):
        client = Client(enforce_csrf_checks=True)
        page = client.get(reverse("home"))
        self.assertEqual(page.status_code, 200)
        html = page.content.decode()
        self.assertIn("/api/investigations/analyze/", html)
        self.assertIn("investigations/app.js", html)
        self.assertIn("Python traceback analysis", html)
        javascript = Path("investigations/static/investigations/app.js").read_text(encoding="utf-8")
        self.assertIn("AbortController", javascript)
        self.assertIn("LIMITED ANALYSIS", javascript)
        self.assertIn("reset-button", javascript)
        self.assertIn('"X-CSRFToken": csrfToken', javascript)
        self.assertIn("processing.hidden = true", javascript)
        template = Path("investigations/templates/investigations/index.html").read_text(encoding="utf-8")
        self.assertIn("id=\"processing\"", template)
        self.assertLess(template.index("Parsing traceback"), template.index("Retrieving source evidence"))
        self.assertLess(template.index("Generating diagnosis with Gemma"), template.index("Validating evidence"))
        token_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', html)
        self.assertIsNotNone(token_match)
        token = token_match.group(1)
        self.assertIn("csrftoken", client.cookies)
        payload = json.dumps({"traceback": 'Traceback (most recent call last):\n  File "missing.py", line 1, in fail\nRuntimeError: broken'})
        denied = client.post(reverse("analyze-investigation"), data=payload, content_type="application/json")
        self.assertEqual(denied.status_code, 403)
        accepted = client.post(reverse("analyze-investigation"), data=payload, content_type="application/json",
                               HTTP_X_CSRFTOKEN=token)
        self.assertEqual(accepted.status_code, 503)
        self.assertEqual(accepted.json()["diagnosis_mode"], "fallback")

    @override_settings(GEMINI_API_KEY="", BASE_DIR=Path("/tmp/tracegraph-no-sources"))
    def test_missing_source_returns_stable_fallback_schema(self):
        traceback = 'Traceback (most recent call last):\n  File "not_here.py", line 8, in fail\nRuntimeError: broken'
        response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")
        self.assertEqual(response.status_code, 503)
        body = response.json()
        self.assertEqual(set(body), {"diagnosis_mode", "summary", "likely_cause", "evidence", "hypotheses", "recommended_steps", "limitations", "traceback_facts", "source_facts", "graph_relationships", "graphify_status", "exception_type"})
        self.assertEqual(body["evidence"], [])
        self.assertEqual(body["exception_type"], "RuntimeError")

    @override_settings(GEMINI_API_KEY="test-key")
    def test_mocked_model_response_filters_uncited_and_invalid_line_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('first\nSECRET_KEY = "supersecretvalue"\nthird\n', encoding="utf-8")
            traceback = f'Traceback (most recent call last):\n  File "{root / "app.py"}", line 2, in fail\nValueError: api_key=tracebacksecret'
            payload = {
                "summary": "A failure", "likely_cause": "Example cause",
                "evidence": [
                    {"source_path": "app.py", "start_line": 2, "end_line": 2, "explanation": "Relevant line"},
                    {"source_path": "../secret.py", "start_line": 1, "end_line": 1, "explanation": "bad"},
                    {"source_path": "app.py", "start_line": 1, "end_line": 40, "explanation": "bad range"},
                ],
                "hypotheses": ["Maybe input"], "recommended_steps": ["Check input"], "limitations": [],
            }
            # Gemma may wrap its JSON answer in a Markdown code fence.
            response_object = Mock(text=f"```json\n{json.dumps(payload)}\n```")
            with override_settings(BASE_DIR=root), patch("google.genai.Client") as client_class:
                client_class.return_value.models.generate_content.return_value = response_object
                response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")
            prompt = client_class.return_value.models.generate_content.call_args.kwargs["contents"]
            self.assertNotIn("supersecretvalue", prompt)
            self.assertNotIn("tracebacksecret", prompt)
            self.assertNotIn(str(root), prompt)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body["evidence"]), 1)
        self.assertEqual(body["evidence"][0]["source_path"], "app.py")
        self.assertEqual(body["diagnosis_mode"], "gemma")
        self.assertEqual(body["graphify_status"], "unavailable")
        self.assertEqual(body["exception_type"], "ValueError")

    @override_settings(GEMINI_API_KEY="test-key", BASE_DIR=Path("/tmp/tracegraph-api-error"))
    def test_empty_max_tokens_response_uses_gemma_safe_generation_settings(self):
        traceback = 'Traceback (most recent call last):\n  File "missing.py", line 1, in fail\nRuntimeError: broken'
        # This matches the live SDK shape when its token budget is consumed
        # before it emits any user-visible text.
        response_object = Mock(text=None, candidates=[Mock(finish_reason="MAX_TOKENS", content=Mock(parts=[]))])
        with patch("google.genai.Client") as client_class:
            client_class.return_value.models.generate_content.return_value = response_object
            response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["diagnosis_mode"], "fallback")
        config = client_class.return_value.models.generate_content.call_args.kwargs["config"]
        self.assertEqual(config.thinking_config.thinking_level, "MINIMAL")
        self.assertGreaterEqual(config.max_output_tokens, 4_096)
        self.assertIsNone(config.response_mime_type)

    @override_settings(GEMINI_API_KEY="test-key", BASE_DIR=Path("/tmp/tracegraph-api-error"))
    def test_model_api_error_returns_stable_fallback(self):
        traceback = 'Traceback (most recent call last):\n  File "missing.py", line 1, in fail\nRuntimeError: broken'
        with patch("google.genai.Client", side_effect=RuntimeError("private SDK detail")):
            response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")
        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body["diagnosis_mode"], "fallback")
        self.assertNotIn("private SDK detail", json.dumps(body))
        self.assertIn("request failed", body["likely_cause"])

    @override_settings(GEMINI_API_KEY="test-key", BASE_DIR=Path("/tmp/tracegraph-api-error"))
    def test_malformed_live_text_is_classified_without_logging_its_contents(self):
        traceback = 'Traceback (most recent call last):\n  File "missing.py", line 1, in fail\nRuntimeError: broken'
        sensitive_output = "private diagnostic content that must not be logged"
        with patch("google.genai.Client") as client_class:
            client_class.return_value.models.generate_content.return_value = Mock(text=f"prefix {sensitive_output}")
            with self.assertLogs("investigations.services.analysis", level="WARNING") as captured:
                response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(captured.records[0].failure_category, "malformed_json")
        self.assertNotIn(sensitive_output, captured.output[0])
        self.assertIn("not a usable JSON diagnosis", response.json()["likely_cause"])

    def test_upstream_errors_have_distinct_safe_categories(self):
        class SDKError(Exception):
            def __init__(self, code):
                self.code = code

        cases = ((SDKError(401), "authentication", 502), (SDKError(403), "permission", 502),
                 (SDKError(429), "quota", 429), (SDKError(504), "timeout", 504),
                 (ConnectionError("hidden"), "network", 503))
        for error, category, status in cases:
            with self.subTest(category=category):
                result = _upstream_failure(error)
                self.assertEqual((result[0], result[2]), (category, status))

    @override_settings(GEMINI_API_KEY="test-key", BASE_DIR=Path("/tmp/tracegraph-api-error"))
    def test_timeout_and_quota_errors_are_identified_without_sdk_details(self):
        traceback = 'Traceback (most recent call last):\n  File "missing.py", line 1, in fail\nRuntimeError: broken'

        class SimulatedTimeout(Exception):
            pass

        class SimulatedQuota(Exception):
            code = 429

        for error, expected, status_code in ((SimulatedTimeout("timeout detail"), "timed out", 504),
                                             (SimulatedQuota("quota detail"), "quota or rate limit", 429)):
            with self.subTest(error=type(error).__name__), patch("google.genai.Client", side_effect=error):
                response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")
            self.assertEqual(response.status_code, status_code)
            self.assertIn(expected, response.json()["likely_cause"])
            self.assertNotIn(str(error), json.dumps(response.json()))

    @override_settings(GEMINI_API_KEY="test-key", BASE_DIR=Path("/tmp/tracegraph-api-error"))
    def test_malformed_model_response_returns_fallback(self):
        traceback = 'Traceback (most recent call last):\n  File "missing.py", line 1, in fail\nRuntimeError: broken'
        with patch("google.genai.Client") as client_class:
            client_class.return_value.models.generate_content.return_value = Mock(text="not json")
            response = self.client.post(self.url, data=json.dumps({"traceback": traceback}), content_type="application/json")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["diagnosis_mode"], "fallback")
