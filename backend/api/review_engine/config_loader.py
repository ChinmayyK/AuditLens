"""
Config Loader — Hot-reloading config from review_config.json.

CRITICAL HACKATHON CONSTRAINT:
  "All detection rules and scoring weights must be loaded from
   a review_config.json file. Hardcoding rules disqualifies the team.
   Judges will add a new rule to the config and expect it to work
   immediately."

This module reads review_config.json from disk on EVERY call.
No caching. No startup-time loading. Pure hot-reload.
"""
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to the single source of truth
_CONFIG_PATH = Path(__file__).parent.parent / "review_config.json"


from typing import Optional


def load_config(config_path: Optional[Path] = None) -> dict:
    """
    Load review_config.json from disk.

    This function is called on EVERY review request to ensure
    judges can edit the file and the next request picks up
    the changes immediately.

    Args:
        config_path: Override path (for testing). Defaults to
            api/review_config.json.

    Returns:
        Parsed config dict with keys: weights, thresholds, custom_rules.
    """
    path = config_path or _CONFIG_PATH

    try:
        with open(path, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(
            f"review_config.json not found at {path}. "
            f"Using empty config — scoring will be broken!"
        )
        return {"weights": {}, "thresholds": {}, "custom_rules": []}
    except json.JSONDecodeError as e:
        logger.error(
            f"Invalid JSON in review_config.json: {e}. "
            f"Using empty config — scoring will be broken!"
        )
        return {"weights": {}, "thresholds": {}, "custom_rules": []}

    logger.debug(
        f"Config hot-reloaded from {path}: "
        f"{len(config.get('custom_rules', []))} rules, "
        f"{len(config.get('weights', {}))} weight groups"
    )

    return config
