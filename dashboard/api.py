from __future__ import annotations

import os
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


POLICY_PATH = Path(os.environ.get("HERMES_RBAC_POLICY", "~/.hermes/rbac_policy.yaml")).expanduser()

router = APIRouter()


class PolicyBody(BaseModel):
    yaml_text: str


@router.get("/policy")
async def get_policy():
    if not POLICY_PATH.exists():
        return {"yaml_text": ""}
    return {"yaml_text": POLICY_PATH.read_text(encoding="utf-8")}


@router.put("/policy")
async def put_policy(body: PolicyBody):
    try:
        parsed = yaml.safe_load(body.yaml_text) or {}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Policy must be a YAML mapping")
    if "roles" not in parsed or "users" not in parsed:
        raise HTTPException(status_code=400, detail="Policy must include roles and users")

    POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_PATH.write_text(body.yaml_text, encoding="utf-8")
    return {"ok": True}
