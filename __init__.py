from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

POLICY_PATH = Path(os.environ.get("HERMES_RBAC_POLICY", "~/.hermes/rbac_policy.yaml")).expanduser()
AUDIT_PATH = Path(os.environ.get("HERMES_RBAC_AUDIT_LOG", "~/.hermes/rbac_audit.log")).expanduser()
DEFAULT_REPORTS_PATH = Path("~/.hermes/work_rbac_reports.jsonl").expanduser()
DEFAULT_EVENTS_PATH = Path("~/.hermes/work_rbac_conversations.jsonl").expanduser()
DEFAULT_HERMES_BIN = shutil.which("hermes") or "hermes"

_REPORT_LOCK = threading.RLock()
_REPORT_SESSIONS: dict[str, dict[str, Any]] = {}
_SESSION_BY_PLATFORM_USER: dict[tuple[str, str], str] = {}
_REPORT_THREAD_STARTED = False

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)(bearer)\s+[a-z0-9._~+/=-]{16,}"),
]

PATH_TOOL_OPERATIONS = {
    "read_file": ("read", "read_roots", "path"),
    "search_files": ("search", "read_roots", "path"),
    "write_file": ("write", "write_roots", "path"),
    "patch": ("patch", "write_roots", "path"),
}


def register(ctx):
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch)
    ctx.register_hook("post_llm_call", _post_llm_call)


def _pre_tool_call(tool_name: str, args: dict[str, Any] | None = None, **_: Any) -> dict[str, str] | None:
    args = args if isinstance(args, dict) else {}
    policy = _load_policy()
    role_name = _role_name(policy)
    role = _role(policy, role_name)

    if not _tool_allowed(role, tool_name):
        message = _tool_denial_message(role_name, role, tool_name)
        _audit(tool_name, "", False, message)
        _record_tool_event(policy, role_name, tool_name, "", False, message)
        return {"action": "block", "message": message}

    if tool_name not in PATH_TOOL_OPERATIONS:
        _audit(tool_name, "", True, "")
        _record_tool_event(policy, role_name, tool_name, "", True, "")
        return None

    operation, roots_key, arg_name = PATH_TOOL_OPERATIONS[tool_name]
    paths = _paths_for_tool(tool_name, args)
    for path in paths:
        if not _under_root(path, role.get(roots_key) or []):
            message = _path_denial_message(role_name, operation, path, roots_key, role.get(roots_key) or [])
            _audit(operation, path, False, message)
            _record_tool_event(policy, role_name, operation, path, False, message)
            return {"action": "block", "message": message}

    for path in paths or [""]:
        _audit(operation, path, True, "")
    _record_tool_event(policy, role_name, operation, path, True, "")
    return None


def _tool_allowed(role: dict[str, Any], tool_name: str) -> bool:
    allowed = role.get("allowed_tools") or []
    if not isinstance(allowed, list):
        return False
    normalized = {str(item) for item in allowed}
    return "*" in normalized or str(tool_name or "") in normalized


def _tool_denial_message(role_name: str, role: dict[str, Any], tool_name: str) -> str:
    base = f"RBAC denied: role '{role_name}' cannot use tool {tool_name!r}; it is not in allowed_tools."
    return f"{base} Allowed tools: {_format_allowed_tools(role)}."


def _path_denial_message(role_name: str, operation: str, path: str, roots_key: str, roots: list[Any]) -> str:
    action = "read/search" if roots_key == "read_roots" else "write/patch"
    roots_text = _format_roots(roots)
    resolved = _real(path)
    return (
        f"RBAC denied: role '{role_name}' cannot {action} {path!r}; "
        f"resolved path is {resolved!r}, which is outside {roots_key}. "
        f"Allowed {roots_key}: {roots_text}. "
        f"Use a path under one of those roots. Relative paths are resolved from the Hermes gateway working directory."
    )


def _format_roots(roots: list[Any]) -> str:
    values = [str(root) for root in roots or [] if str(root).strip()]
    if not values:
        return "(none)"
    return ", ".join(repr(value) for value in values)


def _format_allowed_tools(role: dict[str, Any]) -> str:
    allowed = role.get("allowed_tools") or []
    if not isinstance(allowed, list) or not allowed:
        return "(none)"
    return ", ".join(repr(str(item)) for item in allowed)


def _pre_gateway_dispatch(event: Any = None, **_: Any) -> None:
    policy = _load_policy()
    reporting = _reporting(policy)
    if not reporting.get("enabled"):
        return None

    source = getattr(event, "source", None)
    if source is None:
        return None

    platform = _platform_value(getattr(source, "platform", ""))
    user_id = str(getattr(source, "user_id", "") or "").strip()
    if not platform or not user_id:
        return None

    role_name = _role_name_for_identity(policy, platform, user_id)
    if role_name not in _report_roles(reporting):
        return None
    if reporting.get("dm_only", True) and str(getattr(source, "chat_type", "dm") or "dm") != "dm":
        return None

    text = str(getattr(event, "text", "") or "").strip()
    if not text:
        return None

    _ensure_report_thread()
    session_key = _session_key_for_source(source)
    now = _now()
    with _REPORT_LOCK:
        session = _get_or_reset_session(session_key, source, role_name, now)
        session["last_seen"] = now
        session["events"].append(
            {
                "ts": _iso(now),
                "kind": "user",
                "text": _clean_text(text, reporting),
            }
        )
        session["events"] = session["events"][-_max_events(reporting):]
        _SESSION_BY_PLATFORM_USER[(platform, user_id)] = session_key
    _write_jsonl(_events_path(reporting), _event_record(session_key, source, role_name, "user", text, reporting))
    return None


def _post_llm_call(
    session_id: str = "",
    user_message: Any = None,
    assistant_response: Any = None,
    platform: str = "",
    **_: Any,
) -> None:
    policy = _load_policy()
    reporting = _reporting(policy)
    if not reporting.get("enabled"):
        return None

    platform_s, user_id = _session_identity()
    if not platform_s:
        platform_s = str(platform or "").strip()

    session_key = _active_session_key(str(session_id or ""), platform_s, user_id)
    if not session_key:
        return None

    with _REPORT_LOCK:
        known_session = _REPORT_SESSIONS.get(session_key) or {}
    role_name = (
        str(known_session.get("role") or "")
        or (_role_name_for_identity(policy, platform_s, user_id) if platform_s and user_id else _role_name(policy))
    )
    if role_name not in _report_roles(reporting):
        return None

    text = str(assistant_response or "").strip()
    if not text:
        return None

    _ensure_report_thread()
    now = _now()
    with _REPORT_LOCK:
        session = _REPORT_SESSIONS.get(session_key)
        if not session:
            return None
        session["last_seen"] = now
        session["events"].append(
            {
                "ts": _iso(now),
                "kind": "assistant",
                "text": _clean_text(text, reporting),
            }
        )
        session["events"] = session["events"][-_max_events(reporting):]
    _write_jsonl(_events_path(reporting), {"ts": _iso(now), "session_key": session_key, "kind": "assistant", "text": _clean_text(text, reporting)})
    return None


def _paths_for_tool(tool_name: str, args: dict[str, Any]) -> list[str]:
    if tool_name == "patch" and args.get("mode") == "patch":
        patch = str(args.get("patch") or "")
        paths: list[str] = []
        for line in patch.splitlines():
            prefix = "*** Update File: "
            if line.startswith(prefix):
                paths.append(line[len(prefix):].strip())
                continue
            prefix = "*** Add File: "
            if line.startswith(prefix):
                paths.append(line[len(prefix):].strip())
                continue
            prefix = "*** Delete File: "
            if line.startswith(prefix):
                paths.append(line[len(prefix):].strip())
        return paths

    path = args.get("path")
    return [str(path)] if path else []


def _load_policy() -> dict[str, Any]:
    try:
        with POLICY_PATH.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        logger.exception("Failed to load RBAC policy: %s", POLICY_PATH)
        return {}


def _session_identity() -> tuple[str, str]:
    try:
        from gateway.session_context import get_session_env

        platform = get_session_env("HERMES_SESSION_PLATFORM", "")
        user_id = get_session_env("HERMES_SESSION_USER_ID", "")
    except Exception:
        platform = os.getenv("HERMES_SESSION_PLATFORM", "")
        user_id = os.getenv("HERMES_SESSION_USER_ID", "")
    return str(platform or "").strip(), str(user_id or "").strip()


def _role_name(policy: dict[str, Any]) -> str:
    platform, user_id = _session_identity()
    if not platform and not user_id:
        return "owner"

    return _role_name_for_identity(policy, platform, user_id)


def _role_name_for_identity(policy: dict[str, Any], platform: str, user_id: str) -> str:
    principal = f"{platform}:{user_id}" if platform and user_id else user_id
    users = policy.get("users") or {}
    entry = users.get(principal) if isinstance(users, dict) else None
    if isinstance(entry, dict) and entry.get("role"):
        return str(entry["role"])
    return str(policy.get("default_role") or "guest")


def _role(policy: dict[str, Any], role_name: str) -> dict[str, Any]:
    roles = policy.get("roles") or {}
    role = roles.get(role_name) if isinstance(roles, dict) else None
    return role if isinstance(role, dict) else {}


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(path or ""))


def _under_root(path: str, roots: list[Any]) -> bool:
    real_path = _real(path)
    for raw_root in roots or []:
        root = _real(str(raw_root))
        if root == "/":
            return True
        if real_path == root or real_path.startswith(root.rstrip("/") + "/"):
            return True
    return False


def _audit(operation: str, target: str, allowed: bool, reason: str) -> None:
    try:
        platform, user_id = _session_identity()
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "platform": platform,
            "user_id": user_id,
            "role": _role_name(_load_policy()),
            "operation": operation,
            "target": target,
            "allowed": allowed,
            "reason": reason,
        }
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        logger.debug("RBAC audit write failed", exc_info=True)


def _reporting(policy: dict[str, Any]) -> dict[str, Any]:
    reporting = policy.get("reporting") or {}
    return reporting if isinstance(reporting, dict) else {}


def _report_roles(reporting: dict[str, Any]) -> set[str]:
    roles = reporting.get("report_roles") or ["guest"]
    if not isinstance(roles, list):
        return {"guest"}
    return {str(role) for role in roles}


def _max_events(reporting: dict[str, Any]) -> int:
    try:
        return max(1, int(reporting.get("max_events", 80)))
    except Exception:
        return 80


def _events_path(reporting: dict[str, Any]) -> Path:
    return Path(str(reporting.get("events_log") or DEFAULT_EVENTS_PATH)).expanduser()


def _reports_path(reporting: dict[str, Any]) -> Path:
    return Path(str(reporting.get("reports_log") or DEFAULT_REPORTS_PATH)).expanduser()


def _now() -> float:
    return time.time()


def _iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or _now(), timezone.utc).isoformat()


def _platform_value(platform: Any) -> str:
    return str(getattr(platform, "value", platform) or "").strip()


def _session_key_for_source(source: Any) -> str:
    try:
        from gateway.session import build_session_key

        return str(build_session_key(source))
    except Exception:
        platform = _platform_value(getattr(source, "platform", ""))
        chat_type = str(getattr(source, "chat_type", "dm") or "dm")
        chat_id = str(getattr(source, "chat_id", "") or "")
        user_id = str(getattr(source, "user_id", "") or "")
        thread_id = str(getattr(source, "thread_id", "") or "")
        parts = ["agent:main", platform, chat_type, chat_id or user_id]
        if thread_id:
            parts.append(thread_id)
        return ":".join(part for part in parts if part)


def _get_or_reset_session(session_key: str, source: Any, role_name: str, now: float) -> dict[str, Any]:
    session = _REPORT_SESSIONS.get(session_key)
    if session and session.get("reported"):
        session = None
    if not session:
        session = {
            "session_key": session_key,
            "platform": _platform_value(getattr(source, "platform", "")),
            "chat_id": str(getattr(source, "chat_id", "") or ""),
            "chat_type": str(getattr(source, "chat_type", "dm") or "dm"),
            "user_id": str(getattr(source, "user_id", "") or ""),
            "user_name": str(getattr(source, "user_name", "") or ""),
            "role": role_name,
            "started_at": now,
            "last_seen": now,
            "events": [],
            "tools": [],
            "reported": False,
        }
        _REPORT_SESSIONS[session_key] = session
    return session


def _active_session_key(session_id: str, platform: str, user_id: str) -> str:
    with _REPORT_LOCK:
        if session_id and session_id in _REPORT_SESSIONS:
            return session_id
        if platform and user_id:
            key = _SESSION_BY_PLATFORM_USER.get((platform, user_id))
            if key:
                return key
        candidates = [
            (key, session)
            for key, session in _REPORT_SESSIONS.items()
            if (not platform or session.get("platform") == platform)
            and (not user_id or session.get("user_id") == user_id)
            and not session.get("reported")
        ]
        if not candidates:
            return ""
        candidates.sort(key=lambda item: float(item[1].get("last_seen") or 0), reverse=True)
        return candidates[0][0]


def _record_tool_event(policy: dict[str, Any], role_name: str, operation: str, target: str, allowed: bool, reason: str) -> None:
    reporting = _reporting(policy)
    if not reporting.get("enabled") or role_name not in _report_roles(reporting):
        return
    platform, user_id = _session_identity()
    session_key = _active_session_key("", platform, user_id)
    if not session_key:
        return
    now = _now()
    event = {
        "ts": _iso(now),
        "kind": "tool",
        "operation": operation,
        "target": target,
        "allowed": bool(allowed),
        "reason": reason,
    }
    with _REPORT_LOCK:
        session = _REPORT_SESSIONS.get(session_key)
        if not session:
            return
        session["last_seen"] = now
        session["tools"].append(event)
        session["tools"] = session["tools"][-_max_events(reporting):]
    _write_jsonl(_events_path(reporting), {"session_key": session_key, **event})


def _ensure_report_thread() -> None:
    global _REPORT_THREAD_STARTED
    if _REPORT_THREAD_STARTED:
        return
    with _REPORT_LOCK:
        if _REPORT_THREAD_STARTED:
            return
        thread = threading.Thread(target=_report_loop, name="work-rbac-reporter", daemon=True)
        thread.start()
        _REPORT_THREAD_STARTED = True


def _report_loop() -> None:
    while True:
        policy = _load_policy()
        reporting = _reporting(policy)
        interval = _scan_interval(reporting)
        try:
            if reporting.get("enabled"):
                _flush_idle_reports(policy, reporting)
        except Exception:
            logger.debug("work-rbac reporter loop failed", exc_info=True)
        time.sleep(interval)


def _scan_interval(reporting: dict[str, Any]) -> int:
    try:
        return max(5, int(reporting.get("scan_interval_seconds", 30)))
    except Exception:
        return 30


def _idle_seconds(reporting: dict[str, Any]) -> int:
    try:
        return max(1, int(float(reporting.get("idle_minutes", 5)) * 60))
    except Exception:
        return 300


def _flush_idle_reports(policy: dict[str, Any], reporting: dict[str, Any]) -> None:
    deadline = _now() - _idle_seconds(reporting)
    ready: list[dict[str, Any]] = []
    with _REPORT_LOCK:
        for session in _REPORT_SESSIONS.values():
            if session.get("reported"):
                continue
            if not session.get("events"):
                continue
            if float(session.get("last_seen") or 0) > deadline:
                continue
            session["reported"] = True
            session["reported_at"] = _now()
            ready.append(json.loads(json.dumps(session, ensure_ascii=False)))

    for session in ready:
        report = _build_report(session, reporting)
        record = {
            "ts": _iso(),
            "session_key": session.get("session_key"),
            "platform": session.get("platform"),
            "chat_id": session.get("chat_id"),
            "user_id": session.get("user_id"),
            "role": session.get("role"),
            "report": report,
        }
        _write_jsonl(_reports_path(reporting), record)
        for target in _report_targets(reporting):
            _send_report(target, report)


def _report_targets(reporting: dict[str, Any]) -> list[str]:
    targets = reporting.get("send_to") or []
    if isinstance(targets, str):
        targets = [targets]
    return [str(target).strip() for target in targets if str(target).strip()]


def _build_report(session: dict[str, Any], reporting: dict[str, Any]) -> str:
    who = session.get("user_name") or session.get("user_id") or "unknown"
    platform = session.get("platform") or "unknown"
    chat_id = session.get("chat_id") or "unknown"
    started = _local_time(float(session.get("started_at") or _now()))
    ended = _local_time(float(session.get("last_seen") or _now()))
    lines = [
        "Hermes 访客会话总结",
        f"对象：{who}",
        f"平台：{platform}",
        f"会话：{chat_id}",
        f"时间：{started} - {ended}",
        "",
        "对话：",
    ]
    for event in session.get("events", [])[-_max_events(reporting):]:
        speaker = "访客" if event.get("kind") == "user" else "Hermes"
        text = str(event.get("text") or "").replace("\n", " ").strip()
        lines.append(f"- {speaker}：{text}")

    tools = session.get("tools") or []
    if tools:
        lines.extend(["", "工具 / 权限："])
        for event in tools[-20:]:
            status = "允许" if event.get("allowed") else "拒绝"
            target = str(event.get("target") or "").strip()
            suffix = f" -> {target}" if target else ""
            reason = f"；{event.get('reason')}" if event.get("reason") else ""
            lines.append(f"- {status} {event.get('operation')}{suffix}{reason}")

    return "\n".join(lines)


def _local_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _send_report(target: str, report: str) -> None:
    hermes_bin = os.environ.get("HERMES_BIN", DEFAULT_HERMES_BIN)
    try:
        subprocess.run(
            [hermes_bin, "send", "--to", target, "--subject", "[Hermes 访客会话总结]", "-q", report],
            check=False,
            timeout=45,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        logger.debug("work-rbac report delivery failed: %s", target, exc_info=True)


def _event_record(session_key: str, source: Any, role_name: str, kind: str, text: str, reporting: dict[str, Any]) -> dict[str, Any]:
    return {
        "ts": _iso(),
        "session_key": session_key,
        "platform": _platform_value(getattr(source, "platform", "")),
        "chat_id": str(getattr(source, "chat_id", "") or ""),
        "chat_type": str(getattr(source, "chat_type", "") or ""),
        "user_id": str(getattr(source, "user_id", "") or ""),
        "user_name": str(getattr(source, "user_name", "") or ""),
        "role": role_name,
        "kind": kind,
        "text": _clean_text(text, reporting),
    }


def _clean_text(text: str, reporting: dict[str, Any]) -> str:
    cleaned = str(text or "")
    if reporting.get("redact_secrets", True):
        for pattern in _SECRET_PATTERNS:
            cleaned = pattern.sub(lambda match: f"{match.group(1)} [REDACTED]", cleaned)
    try:
        limit = max(80, int(reporting.get("max_message_chars", 500)))
    except Exception:
        limit = 500
    cleaned = cleaned.strip()
    if len(cleaned) > limit:
        return cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def _write_jsonl(path: Path, record: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        logger.debug("work-rbac jsonl write failed: %s", path, exc_info=True)
