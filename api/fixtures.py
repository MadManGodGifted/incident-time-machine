"""Vercel Serverless Function: GET /api/fixtures"""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from api.index import handler

__all__ = ["handler"]
