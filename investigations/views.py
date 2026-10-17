import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from investigations.services.analysis import InvalidTraceback, analyze_traceback
from investigations.services.github import GitHubRepositoryError, InvalidRepository


def home(request):
    return render(request, "investigations/index.html")


@require_POST
def analyze_investigation(request):
    """Analyze a Python traceback and return a stable diagnosis document."""
    if request.content_type != "application/json":
        return JsonResponse({"error": "Content-Type must be application/json"}, status=415)
    if len(request.body) > 350_000:
        return JsonResponse({"error": "Request body is too large"}, status=413)
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return JsonResponse({"error": "Request body must be valid JSON"}, status=400)
    if not isinstance(body, dict) or not isinstance(body.get("traceback"), str):
        return JsonResponse({"error": "Request JSON must include a string 'traceback' field"}, status=400)
    repository = body.get("repository")
    if repository is not None and (not isinstance(repository, str) or len(repository) > 512):
        return JsonResponse({"error": "'repository' must be a GitHub repository identifier string"}, status=400)
    if any(key in body for key in ("token", "github_token", "access_token", "credentials")):
        return JsonResponse({"error": "Credentials must be configured on the server, not included in the request"}, status=400)
    try:
        outcome = analyze_traceback(body["traceback"], repository=repository or None)
        return JsonResponse(outcome.document, status=outcome.status_code)
    except InvalidTraceback as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except InvalidRepository as exc:
        return JsonResponse({"error": str(exc)}, status=400)
    except GitHubRepositoryError as exc:
        return JsonResponse({"error": exc.message}, status=exc.status_code)
    except Exception:
        # Do not leak filesystem paths, SDK details, or configuration into API errors.
        return JsonResponse({"error": "Analysis could not be completed."}, status=500)
