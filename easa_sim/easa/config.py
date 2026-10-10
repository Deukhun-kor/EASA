"""YAML configuration loading with dotted-key overrides and deep merge."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def apply_dotted(cfg: dict, assignments: list[str]) -> dict:
    """Apply CLI overrides of the form a.b.c=value (YAML-parsed value)."""
    out = copy.deepcopy(cfg)
    for a in assignments or []:
        key, _, raw = a.partition("=")
        value = yaml.safe_load(raw)
        node = out
        parts = key.split(".")
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    return out


def materialise(cfg: dict, config_name: str) -> dict:
    """Return the full config for one named configuration (Table 3 row)."""
    overrides = cfg.get("configs", {}).get(config_name)
    if overrides is None:           # follow-up ablations live under extra_configs (never part of the default grid)
        overrides = cfg.get("extra_configs", {}).get(config_name)
    if overrides is None:
        raise KeyError(f"unknown configuration '{config_name}'; "
                       f"available: {list(cfg.get('configs', {})) + list(cfg.get('extra_configs', {}))}")
    full = deep_merge(cfg, overrides)
    full["experiment"]["config_name"] = config_name
    return full
