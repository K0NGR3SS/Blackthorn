"""Truthful capability metadata for Blackthorn scan techniques.

The registered catalog describes *coverage*, but coverage is not the same as
proof quality.  This module gives the CLI and GUI a small, stable vocabulary for
explaining what each technique can currently produce:

``proof``
    The implementation has a vulnerability-specific confirmation path.
``candidate``
    The implementation can identify a useful differential that still needs
    manual or tool-assisted verification.
``observation``
    The implementation inventories attack surface or configuration only.
``disabled``
    The current transport or proof engine cannot express the check faithfully.

The default is deliberately conservative: a new technique is candidate-capable
until its proof contract is explicitly reviewed.
"""
from __future__ import annotations

from typing import Dict, Iterable, Mapping


PROOF_CAPABLE_TECHNIQUES = frozenset({
    '_test_sqli_bypass',
    '_test_json_sqli_bypass',
    '_test_command_injection_bypass',
    '_test_command_injection_windows',
    '_test_ssti_detection',
    '_test_xxe_detection',
    '_test_crlf_injection',
    '_test_open_redirect',
    '_test_cors_misconfiguration',
    '_test_jwt_oauth_bypass',
    '_test_jwt_attacks',
    '_test_jwt_jwk_injection',
    '_test_oauth_oidc',
    '_test_dom_xss',
    '_test_client_side_path_traversal',
    '_test_cache_poisoning_deep',
    '_test_subdomain_takeover',
    '_test_auth_logic',
})


OBSERVATION_ONLY_TECHNIQUES = frozenset({
    '_test_security_headers',
    '_test_cookie_security',
    '_test_clickjacking',
    '_test_csp_analysis',
    '_test_graphql_csrf',
    '_test_saml_xsw',
    '_test_llm_prompt_injection',
    '_test_grpc_detection',
    '_test_http3_detection',
    '_test_cloud_provider_detection',
    '_test_information_disclosure',
    '_test_api_key_exposure',
    '_test_js_secret_exposure',
    '_detect_waf_rule_version',
    '_detect_javascript_waf',
    '_test_api_endpoint_discovery',
    '_test_dns_zone_transfer',
    '_enumerate_subdomains',
    '_historical_dns_lookup',
    '_certificate_transparency_lookup',
    '_fingerprint_technology_stack',
    '_test_cve_fingerprint',
    '_test_content_discovery',
})


CAPABILITY_LABELS = {
    'proof': 'Proof-capable',
    'candidate': 'Candidate-only',
    'observation': 'Observation-only',
    'disabled': 'Unavailable',
}


def technique_capability(
    name: str,
    *,
    disabled_transport: Iterable[str] = (),
    disabled_accuracy: Iterable[str] = (),
    intrusive: Iterable[str] = (),
    safe_skip: Iterable[str] = (),
) -> Dict[str, object]:
    """Return conservative public metadata for one registered technique."""
    disabled_transport = set(disabled_transport)
    disabled_accuracy = set(disabled_accuracy)
    if name in disabled_transport:
        level = 'disabled'
        reason = 'Requires a faithful raw HTTP transport'
    elif name in set(disabled_accuracy):
        level = 'disabled'
        reason = 'Requires a proof-capable validation workflow'
    elif name in OBSERVATION_ONLY_TECHNIQUES:
        level = 'observation'
        reason = 'Produces inventory or configuration evidence'
    elif name in PROOF_CAPABLE_TECHNIQUES:
        level = 'proof'
        reason = 'Has a vulnerability-specific confirmation path'
    else:
        level = 'candidate'
        reason = 'Differential evidence requires verification'
    return {
        'technique': name,
        'capability': level,
        'label': CAPABILITY_LABELS[level],
        'reason': reason,
        'requires_intrusive': name in set(intrusive),
        'skipped_in_safe_mode': name in set(safe_skip),
    }

def build_capability_catalog(
    categories: Mapping[str, Mapping[str, object]],
    **guard_sets,
) -> Dict[str, Dict[str, object]]:
    """Return metadata for every technique in a category registry."""
    return {
        name: technique_capability(name, **guard_sets)
        for category in categories.values()
        for name in category.get('techniques', [])
    }
