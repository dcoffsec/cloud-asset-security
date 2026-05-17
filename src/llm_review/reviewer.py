"""
LLM-based security review — uses Claude to synthesize findings into
an actionable security assessment.

Design decisions
----------------
- Structured prompt with explicit output schema (JSON) for reliable parsing.
- Findings are summarised to stay within context window — full details
  remain in the structured SecurityFinding objects.
- We pass asset context (type, owner, environment) so the LLM can tailor
  its risk assessment (a Redis port open on a dev box differs from prod).
- Fallback: if the LLM call fails, we generate a deterministic review
  from the structured findings so the pipeline never stalls.
"""
import json
import logging
import time
from typing import Optional

import anthropic

from ..config import get_config
from ..models import Asset, LLMReview, RiskLevel, SecurityFinding

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior application security engineer performing a cloud asset security review.
You will be given metadata about a cloud asset and a list of automated security findings.

Your task is to produce a structured security assessment in JSON format ONLY.
Do not include any text outside the JSON object.

The JSON must have exactly this structure:
{
  "overall_risk": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "executive_summary": "2-3 sentence summary for a non-technical stakeholder",
  "key_findings": ["finding 1", "finding 2", ...],
  "attack_surface_analysis": "Paragraph describing how an attacker would approach this asset",
  "prioritized_actions": [
    {"priority": "1", "action": "...", "effort": "low|medium|high", "impact": "low|medium|high"},
    ...
  ],
  "threat_scenarios": ["Scenario 1: ...", "Scenario 2: ..."],
  "compliance_notes": "Notes on PCI DSS / SOC2 / CIS benchmark implications"
}

Guidelines:
- overall_risk should reflect the WORST actionable finding, not just the highest severity label
- Be specific and technical in action items — name the exact header, port, or config to change
- Threat scenarios should describe realistic attack chains, not generic statements
- Consider the asset's environment (production vs staging) and owner when prioritising
- If no critical findings exist, still provide value by highlighting the defence-in-depth gaps
"""


def build_review_prompt(asset: Asset, findings: list[SecurityFinding]) -> str:
    """Construct the user prompt from asset context and findings."""

    # Asset context
    asset_ctx = {
        "hostname": asset.hostname,
        "asset_type": asset.asset_type.value,
        "environment": asset.environment,
        "owner": asset.owner,
        "team": asset.team,
        "region": asset.region,
        "tags": asset.tags,
    }

    # Summarised findings (avoid blowing the context window)
    finding_summaries = []
    for f in findings:
        finding_summaries.append({
            "id": f.check_id,
            "risk": f.risk_level.value,
            "title": f.title,
            "category": f.category,
            "description": f.description[:300],  # Truncate long descriptions
            "evidence": {k: str(v)[:100] for k, v in (f.evidence or {}).items()},
        })

    finding_counts = {}
    for f in findings:
        finding_counts[f.risk_level.value] = finding_counts.get(f.risk_level.value, 0) + 1

    prompt = f"""Asset under review:
{json.dumps(asset_ctx, indent=2)}

Finding summary: {finding_counts}
Total findings: {len(findings)}

Detailed findings:
{json.dumps(finding_summaries, indent=2)}

Please provide your security assessment as a JSON object."""

    return prompt


def generate_llm_review(
    asset: Asset,
    findings: list[SecurityFinding],
    client: Optional[anthropic.Anthropic] = None,
) -> LLMReview:
    """
    Call Claude to generate a synthesised security review.
    Falls back to a deterministic review if the API call fails.
    """
    config = get_config()

    if not config.anthropic_api_key:
        logger.warning("No ANTHROPIC_API_KEY — using deterministic fallback review")
        return _deterministic_fallback(asset, findings)

    client = client or anthropic.Anthropic(api_key=config.anthropic_api_key)
    prompt = build_review_prompt(asset, findings)

    start = time.time()
    try:
        response = client.messages.create(
            model=config.llm_model,
            max_tokens=config.llm_max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as exc:
        logger.error("LLM API call failed: %s", exc)
        return _deterministic_fallback(asset, findings)

    elapsed = time.time() - start
    raw_text = response.content[0].text if response.content else ""
    tokens_used = response.usage.input_tokens + response.usage.output_tokens

    logger.info("LLM review generated in %.1fs (%d tokens)", elapsed, tokens_used)

    return _parse_llm_response(raw_text, tokens_used, config.llm_model, findings)


def _parse_llm_response(
    raw_text: str,
    tokens_used: int,
    model: str,
    findings: list[SecurityFinding],
) -> LLMReview:
    """Parse the JSON response from the LLM into a structured LLMReview."""
    try:
        # Strip markdown fences if present
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1])

        data = json.loads(text)

        return LLMReview(
            overall_risk=RiskLevel(data.get("overall_risk", "MEDIUM")),
            executive_summary=data.get("executive_summary", ""),
            key_findings=data.get("key_findings", []),
            attack_surface_analysis=data.get("attack_surface_analysis", ""),
            prioritized_actions=data.get("prioritized_actions", []),
            threat_scenarios=data.get("threat_scenarios", []),
            compliance_notes=data.get("compliance_notes", ""),
            raw_response=raw_text,
            model=model,
            tokens_used=tokens_used,
        )
    except (json.JSONDecodeError, ValueError, KeyError) as exc:
        logger.warning("Failed to parse LLM JSON response: %s", exc)
        return _deterministic_fallback_from_text(raw_text, findings, model, tokens_used)


def _deterministic_fallback(asset: Asset, findings: list[SecurityFinding]) -> LLMReview:
    """
    Generate a structured review without the LLM.
    Used when the API key is absent or the call fails.
    Ensures the pipeline always produces output.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.risk_level.value, 99))

    critical = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
    high = [f for f in findings if f.risk_level == RiskLevel.HIGH]

    # Determine overall risk
    if critical:
        overall_risk = RiskLevel.CRITICAL
    elif high:
        overall_risk = RiskLevel.HIGH
    elif any(f.risk_level == RiskLevel.MEDIUM for f in findings):
        overall_risk = RiskLevel.MEDIUM
    elif findings:
        overall_risk = RiskLevel.LOW
    else:
        overall_risk = RiskLevel.INFO

    key_findings = [f"{f.risk_level.value}: {f.title}" for f in sorted_findings[:10]]

    prioritized_actions = [
        {
            "priority": str(i + 1),
            "action": f.remediation or f.title,
            "effort": "low",
            "impact": "high" if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH) else "medium",
        }
        for i, f in enumerate(sorted_findings[:5])
        if f.remediation
    ]

    critical_categories = list({f.category for f in critical})
    threat_scenarios = []
    if "Network Exposure" in critical_categories:
        threat_scenarios.append(
            "Scenario 1: Automated scanner discovers exposed database port; "
            "attacker brute-forces credentials and exfiltrates data."
        )
    if "Admin Access" in critical_categories:
        threat_scenarios.append(
            "Scenario 2: Attacker discovers exposed admin panel via Google dorking; "
            "attempts credential stuffing using leaked password lists."
        )
    if not threat_scenarios:
        threat_scenarios = [
            "Scenario 1: Attacker leverages missing security headers to conduct XSS attack.",
            "Scenario 2: Information disclosure via verbose server headers aids targeted exploitation.",
        ]

    finding_count = len(findings)
    summary = (
        f"The asset '{asset.hostname}' ({asset.environment} environment) has {finding_count} "
        f"security findings including {len(critical)} critical and {len(high)} high severity issues. "
        f"Immediate remediation is required for critical findings to prevent potential compromise."
        if critical else
        f"The asset '{asset.hostname}' has {finding_count} findings with no critical issues. "
        f"High-priority items should be addressed within the next sprint."
    )

    return LLMReview(
        overall_risk=overall_risk,
        executive_summary=summary,
        key_findings=key_findings,
        attack_surface_analysis=(
            f"This {asset.asset_type.value} in the {asset.environment} environment "
            f"exposes {finding_count} attack vectors. "
            f"Primary concerns are in categories: "
            f"{', '.join({f.category for f in sorted_findings[:3]})}."
        ),
        prioritized_actions=prioritized_actions,
        threat_scenarios=threat_scenarios,
        compliance_notes=(
            "Critical and high findings likely violate PCI DSS requirements 6.4 (security patches), "
            "6.6 (WAF), and 8.3 (strong authentication). Review against CIS AWS Foundations Benchmark."
            if critical or high else
            "No immediate compliance violations detected. Review against CIS AWS Foundations Benchmark "
            "for comprehensive coverage."
        ),
        raw_response="[deterministic fallback — no LLM API key configured]",
        model="deterministic",
        tokens_used=0,
    )


def _deterministic_fallback_from_text(
    raw_text: str,
    findings: list[SecurityFinding],
    model: str,
    tokens_used: int,
) -> LLMReview:
    """Parse failure fallback — wraps unparseable LLM text."""
    base = _deterministic_fallback(None, findings)  # type: ignore
    base.raw_response = raw_text
    base.model = model
    base.tokens_used = tokens_used
    return base
