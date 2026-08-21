"""Technology-aware pentest recipes and Nuclei workflow generation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .pentest_models import ImpactLevel, ModelValidationError


_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,127}$")
_TAG_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@dataclass(frozen=True)
class RecipeStage:
    stage_id: str
    stage_type: str
    label: str
    impact: ImpactLevel
    config: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _KEY_RE.fullmatch(str(self.stage_id)):
            raise ModelValidationError("invalid recipe stage id")
        if self.stage_type not in {"module", "tool", "nuclei", "manual"}:
            raise ModelValidationError("invalid recipe stage type")
        object.__setattr__(self, "impact", ImpactLevel.parse(self.impact))
        object.__setattr__(self, "config", dict(self.config or {}))


@dataclass(frozen=True)
class TestingRecipe:
    recipe_id: str
    title: str
    technology_terms: Tuple[str, ...]
    stages: Tuple[RecipeStage, ...]
    description: str = ""

    def __post_init__(self) -> None:
        if not _KEY_RE.fullmatch(str(self.recipe_id)):
            raise ModelValidationError("invalid recipe id")
        terms = tuple(str(term).strip().lower() for term in self.technology_terms if str(term).strip())
        if not terms:
            raise ModelValidationError("recipe requires at least one technology term")
        if not self.stages:
            raise ModelValidationError("recipe requires at least one stage")
        object.__setattr__(self, "technology_terms", terms)


def _stage(stage_id: str, stage_type: str, label: str, impact: ImpactLevel,
           **config: Any) -> RecipeStage:
    return RecipeStage(stage_id, stage_type, label, impact, config)


BUILTIN_RECIPES: Tuple[TestingRecipe, ...] = (
    TestingRecipe(
        "wordpress-review",
        "WordPress authenticated and component review",
        ("wordpress", "wp-content", "wp-json"),
        (
            _stage("wpscan", "tool", "Enumerate WordPress components", ImpactLevel.SAFE,
                   tool="wpscan"),
            _stage("wordpress-nuclei", "nuclei", "Run WordPress-specific templates", ImpactLevel.SAFE,
                   tags=("wordpress",)),
            _stage("role-diff", "module", "Compare authenticated WordPress roles", ImpactLevel.SAFE,
                   module="role-differential"),
        ),
    ),
    TestingRecipe(
        "graphql-review",
        "GraphQL schema and resolver authorization review",
        ("graphql", "apollo", "graphiql"),
        (
            _stage("graphql-schema", "module", "Extract schema and operation inventory", ImpactLevel.SAFE,
                   module="graphql-schema"),
            _stage("graphql-role-diff", "module", "Compare resolver fields across roles", ImpactLevel.SAFE,
                   module="role-differential"),
            _stage("graphql-nuclei", "nuclei", "Run GraphQL templates", ImpactLevel.SAFE,
                   tags=("graphql",)),
            _stage("graphql-depth", "module", "Test bounded query depth and batching", ImpactLevel.INTRUSIVE,
                   module="graphql-depth", max_depth=8),
        ),
    ),
    TestingRecipe(
        "microsoft-web-review",
        "IIS and ASP.NET review",
        ("iis", "asp.net", "viewstate", "microsoft-httpapi"),
        (
            _stage("iis-nuclei", "nuclei", "Run IIS and ASP.NET templates", ImpactLevel.SAFE,
                   tags=("iis", "aspnet")),
            _stage("viewstate", "module", "Inspect ViewState protection", ImpactLevel.SAFE,
                   module="viewstate"),
            _stage("windows-paths", "module", "Test Windows path normalization", ImpactLevel.SAFE,
                   module="windows-path-normalization"),
        ),
    ),
    TestingRecipe(
        "kubernetes-review",
        "Kubernetes exposure and authorization review",
        ("kubernetes", "kube-apiserver", "k8s"),
        (
            _stage("k8s-nuclei", "nuclei", "Run Kubernetes exposure templates", ImpactLevel.SAFE,
                   tags=("kubernetes",)),
            _stage("k8s-api", "module", "Enumerate API discovery endpoints", ImpactLevel.SAFE,
                   module="kubernetes-api"),
            _stage("k8s-authz", "module", "Review effective API permissions", ImpactLevel.INTRUSIVE,
                   module="kubernetes-authz"),
        ),
    ),
    TestingRecipe(
        "object-storage-review",
        "Object storage ownership and access review",
        ("s3", "amazonaws", "azure blob", "google storage", "minio"),
        (
            _stage("storage-enum", "module", "Confirm bucket/container ownership", ImpactLevel.SAFE,
                   module="object-storage-enumeration"),
            _stage("storage-nuclei", "nuclei", "Run storage exposure templates", ImpactLevel.SAFE,
                   tags=("s3", "bucket", "cloud")),
            _stage("storage-write", "module", "Upload and remove an inert ownership canary", ImpactLevel.INTRUSIVE,
                   module="object-storage-canary", cleanup_required=True),
        ),
    ),
    TestingRecipe(
        "websocket-review",
        "WebSocket authentication and message authorization review",
        ("websocket", "socket.io", "wss"),
        (
            _stage("ws-origin", "module", "Test handshake Origin policy", ImpactLevel.SAFE,
                   module="websocket-origin"),
            _stage("ws-role-diff", "module", "Replay messages across identities", ImpactLevel.SAFE,
                   module="websocket-role-differential"),
            _stage("ws-fuzz", "module", "Fuzz bounded message fields", ImpactLevel.INTRUSIVE,
                   module="websocket-message-fuzz"),
        ),
    ),
    TestingRecipe(
        "oauth-oidc-review",
        "OAuth and OpenID Connect flow review",
        ("oauth", "openid", "oidc", "jwks"),
        (
            _stage("oidc-discovery", "module", "Map discovery, issuer, and JWKS", ImpactLevel.SAFE,
                   module="oidc-discovery"),
            _stage("oauth-state", "module", "Test state, nonce, PKCE, and redirect binding", ImpactLevel.SAFE,
                   module="oauth-flow"),
            _stage("jwt-review", "module", "Review token claims and key selection", ImpactLevel.SAFE,
                   module="jwt"),
        ),
    ),
    TestingRecipe(
        "generic-authenticated-web",
        "Authenticated web application review",
        ("http", "https", "web application"),
        (
            _stage("crawl", "tool", "Crawl authenticated routes", ImpactLevel.SAFE, tool="katana"),
            _stage("role-matrix", "module", "Replay captured requests across roles", ImpactLevel.SAFE,
                   module="role-differential"),
            _stage("session", "module", "Test session rotation, logout, and timeout", ImpactLevel.SAFE,
                   module="session-lifecycle"),
            _stage("web-nuclei", "nuclei", "Run technology-selected templates", ImpactLevel.SAFE,
                   tags=("tech", "exposure", "misconfig")),
        ),
    ),
)


@dataclass(frozen=True)
class RecipeMatch:
    recipe: TestingRecipe
    matched_terms: Tuple[str, ...]
    confidence: float


def select_recipes(
    technology_evidence: Iterable[str],
    *,
    include_generic: bool = True,
) -> Tuple[RecipeMatch, ...]:
    evidence = "\n".join(str(item).lower() for item in technology_evidence if str(item).strip())
    matches: List[RecipeMatch] = []
    for recipe in BUILTIN_RECIPES:
        if recipe.recipe_id == "generic-authenticated-web" and not include_generic:
            continue
        terms = tuple(term for term in recipe.technology_terms if term in evidence)
        if terms:
            confidence = min(1.0, 0.55 + (0.15 * len(terms)))
            matches.append(RecipeMatch(recipe, terms, confidence))
    matches.sort(key=lambda item: (-item.confidence, item.recipe.recipe_id))
    return tuple(matches)


def _yaml_scalar(value: str) -> str:
    text = str(value)
    return "'" + text.replace("'", "''") + "'"


def render_nuclei_workflow(
    recipes: Sequence[TestingRecipe],
    *,
    custom_tags: Iterable[str] = (),
) -> str:
    """Render selected Nuclei stages as a strict tag-based workflow.

    Blackthorn performs the technology condition before generating this file,
    which avoids embedding unstable community template paths. Nuclei then runs
    only the selected tag groups instead of spraying the full template catalog.
    """
    tags: List[str] = []
    for recipe in recipes:
        for stage in recipe.stages:
            if stage.stage_type != "nuclei":
                continue
            for tag in stage.config.get("tags", ()):
                text = str(tag)
                if not _TAG_RE.fullmatch(text):
                    raise ModelValidationError("invalid Nuclei workflow tag")
                if text not in tags:
                    tags.append(text)
    for tag in custom_tags:
        text = str(tag)
        if not _TAG_RE.fullmatch(text):
            raise ModelValidationError("invalid custom Nuclei workflow tag")
        if text not in tags:
            tags.append(text)
    if not tags:
        raise ModelValidationError("selected recipes contain no Nuclei stages")
    lines = [
        "# Generated by Blackthorn from already-observed technology evidence.",
        "workflows:",
    ]
    for tag in tags:
        lines.append("  - tags: %s" % _yaml_scalar(tag))
    return "\n".join(lines) + "\n"


def execution_plan(matches: Sequence[RecipeMatch], maximum_impact: ImpactLevel) -> List[Dict[str, Any]]:
    maximum_impact = ImpactLevel.parse(maximum_impact)
    plan: List[Dict[str, Any]] = []
    seen = set()
    for match in matches:
        for stage in match.recipe.stages:
            marker = (stage.stage_type, stage.stage_id)
            if marker in seen:
                continue
            seen.add(marker)
            plan.append({
                "recipe_id": match.recipe.recipe_id,
                "stage_id": stage.stage_id,
                "type": stage.stage_type,
                "label": stage.label,
                "impact": stage.impact.name.lower(),
                "enabled": stage.impact <= maximum_impact,
                "matched_terms": list(match.matched_terms),
                "confidence": match.confidence,
                "config": dict(stage.config),
            })
    return plan

