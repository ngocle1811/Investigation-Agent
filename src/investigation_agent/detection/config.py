"""Detection and correlation configuration loading."""

from pathlib import Path

import yaml

from investigation_agent.detection.schemas import DetectionConfig


def load_detection_config(
    path: Path,
    *,
    allowed_mitre_ids: set[str] | None = None,
) -> DetectionConfig:
    """Load strict rule configuration and optionally validate MITRE mappings."""

    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    config = DetectionConfig.model_validate(payload)
    if allowed_mitre_ids is not None:
        invalid = sorted(
            {
                technique_id
                for rule in config.rules.values()
                for technique_id in rule.mitre_techniques
                if technique_id not in allowed_mitre_ids
            }
        )
        if invalid:
            raise ValueError(
                "Detection rules reference MITRE IDs outside the configured knowledge "
                f"subset: {invalid}"
            )
    return config
