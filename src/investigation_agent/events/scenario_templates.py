"""Scenario catalog loading and deterministic ground-truth validation."""

from pathlib import Path

import yaml

from investigation_agent.events.schemas import ScenarioCatalog, ScenarioTemplate
from investigation_agent.ingestion.pipeline import load_sources_config


def configured_mitre_ids(sources_path: Path) -> set[str]:
    """Return the exact ATT&CK IDs admitted by the current knowledge configuration."""

    sources = load_sources_config(sources_path)
    return set(sources.mitre_attack.technique_allowlist)


def load_scenario_catalog(
    path: Path,
    *,
    allowed_mitre_ids: set[str] | None = None,
) -> ScenarioCatalog:
    """Load strict templates and reject MITRE IDs outside the ingested subset."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    catalog = ScenarioCatalog.model_validate(payload)
    if allowed_mitre_ids is not None:
        invalid = sorted(
            {
                technique_id
                for template in catalog.templates
                for technique_id in template.ground_truth.expected_mitre
                if technique_id not in allowed_mitre_ids
            }
        )
        if invalid:
            raise ValueError(
                "Scenario templates reference MITRE IDs outside the configured knowledge "
                f"subset: {invalid}"
            )
    return catalog


def templates_by_id(catalog: ScenarioCatalog) -> dict[str, ScenarioTemplate]:
    """Return stable scenario dispatch keyed by validated unique IDs."""

    return {template.scenario_id: template for template in catalog.templates}
