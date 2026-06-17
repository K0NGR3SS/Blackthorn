"""
Scan checkpointing for resumable scans.

A long scan that dies (crash, Ctrl-C, dropped connection) shouldn't have to start
over. After each technique the scanner writes a small JSON checkpoint — which
techniques finished and the findings so far — keyed by target. ``--resume`` loads
it, skips completed techniques, and continues.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _checkpoint_path(target: str) -> str:
    try:
        from .config import ensure_config_dir
        base = ensure_config_dir()
    except Exception:
        base = os.path.join(os.path.expanduser('~'), '.wafpierce')
        os.makedirs(base, exist_ok=True)
    digest = hashlib.md5(target.encode()).hexdigest()[:16]
    return os.path.join(base, f"checkpoint_{digest}.json")


def save(target: str, completed: List[str], results: List[Dict[str, Any]]) -> None:
    """Persist progress for ``target`` (best-effort; never raises)."""
    try:
        payload = {
            'target': target,
            'updated_at': time.time(),
            'completed': list(completed),
            'results': results,
        }
        with open(_checkpoint_path(target), 'w', encoding='utf-8') as f:
            json.dump(payload, f, default=str)
    except Exception as e:
        logger.debug(f"Checkpoint save failed: {e}")


def load(target: str) -> Optional[Dict[str, Any]]:
    """Load a saved checkpoint for ``target``, or None if none/invalid."""
    path = _checkpoint_path(target)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if data.get('target') == target:
            return data
    except Exception as e:
        logger.debug(f"Checkpoint load failed: {e}")
    return None


def clear(target: str) -> None:
    """Delete a target's checkpoint (call on clean completion)."""
    try:
        path = _checkpoint_path(target)
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        logger.debug(f"Checkpoint clear failed: {e}")
