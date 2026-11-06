"""Opt-in, fail-soft HTTPS notifications for health and incident observations.

Slice-0 deliberately does not retry and refuses redirects. Webhook settings are
read from the process environment only; the destination is never persisted in
the QTS configuration file.
"""

import hashlib
import hmac
import json
import math
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional

from .redaction import redact_value


SCHEMA = "qnap-nas-cli.webhook.v1"
MAX_BODY_BYTES = 8192
MAX_ITEMS = 8
_TRUTHY = {"1", "true", "yes"}


def webhook_enabled(env: Mapping[str, str] = os.environ) -> bool:
    """Return whether a nonempty webhook URL has been configured."""
    return bool(str(env.get("QTS_WEBHOOK_URL", "")).strip())


def _timeout(env: Mapping[str, str]) -> float:
    raw = env.get("QTS_WEBHOOK_TIMEOUT_SEC", "5")
    try:
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("non-finite timeout")
    except (TypeError, ValueError):
        value = 5.0
    return max(1.0, min(10.0, value))


def _url_parts(url: str):
    try:
        parsed = urllib.parse.urlsplit(url)
        # Accessing hostname/port validates malformed bracket and port syntax.
        host = parsed.hostname
        _ = parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme.lower() != "https" or not host or parsed.username or parsed.password:
        return None
    if any(ord(char) < 32 for char in url):
        return None
    return parsed


def _redacted_url(url: str) -> str:
    parsed = _url_parts(url)
    if parsed is None:
        return "https://<host>/…"
    host = parsed.hostname or "<host>"
    if ":" in host and not host.startswith("["):
        host = "[{}]".format(host)
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = host + ((":{}".format(port)) if port is not None else "")
    return "https://{}/…".format(netloc)


def _text(value: Any, max_chars: Optional[int] = None) -> tuple:
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        return "", False
    rendered = str(value)
    if max_chars is not None and len(rendered) > max_chars:
        return rendered[:max_chars], True
    return rendered, False


def _pick_device(observation: Mapping[str, Any]) -> tuple:
    system = observation.get("system")
    if not isinstance(system, dict):
        report_observations = observation.get("observations")
        health = report_observations.get("health") if isinstance(report_observations, dict) else None
        system = health.get("system") if isinstance(health, dict) else None
    if not isinstance(system, dict):
        candidate = observation.get("device")
        system = candidate if isinstance(candidate, dict) else {}
    device = {}
    truncated = False
    for field in ("model", "firmware", "build"):
        value = system.get(field)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            rendered = str(value)
            if len(rendered) > 120:
                truncated = True
            device[field] = rendered[:120]
    return device, truncated


def _clean_items(items: Any, *, unknown: bool = False):
    cleaned = []
    truncated = False
    if not isinstance(items, list):
        return cleaned, bool(items)
    if len(items) > MAX_ITEMS:
        truncated = True
    for item in items[:MAX_ITEMS]:
        if not isinstance(item, dict):
            truncated = True
            continue
        code, code_truncated = _text(item.get("code", "unknown"), 80)
        entry = {"code": code or "unknown"}
        if not unknown:
            severity, severity_truncated = _text(item.get("severity"), 32)
            if severity:
                entry["severity"] = severity
            else:
                severity_truncated = False
        else:
            severity_truncated = False
        cleaned.append(entry)
        truncated = truncated or code_truncated or severity_truncated
    return cleaned, truncated


def _incident_items(observation: Mapping[str, Any]):
    scan = observation.get("ransomware_scan")
    if not isinstance(scan, dict):
        scan = observation
    indicators = scan.get("indicators", [])
    findings = []
    truncated = False
    if isinstance(indicators, list):
        if len(indicators) > MAX_ITEMS:
            truncated = True
        for indicator in indicators[:MAX_ITEMS]:
            if not isinstance(indicator, dict):
                truncated = True
                continue
            code, was_truncated = _text(indicator.get("code", "incident_indicator"), 80)
            confidence = indicator.get("confidence")
            severity = "critical" if confidence == "high" else "warning" if confidence == "medium" else "info"
            findings.append({"code": code or "incident_indicator", "severity": severity})
            truncated = truncated or was_truncated

    coverage = scan.get("coverage")
    unknowns = []
    if isinstance(coverage, dict):
        issues = coverage.get("issues")
        if (coverage.get("status") == "partial" or coverage.get("truncated") is True or
                coverage.get("depth_limited") is True or (isinstance(issues, list) and issues)):
            unknowns.append({"code": "incident_scan_incomplete"})
    collection_errors = observation.get("collection_errors")
    if isinstance(collection_errors, list) and collection_errors:
        unknowns.append({"code": "incident_collection_incomplete"})
    return findings, unknowns, truncated


def _compact(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def build_payload(
    trigger: str,
    observation: Mapping[str, Any],
    *,
    emitted_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a small allowlisted JSON payload from a health/report observation."""
    if trigger not in ("health.unhealthy", "health.indeterminate", "incident.suspected"):
        raise ValueError("unsupported webhook trigger")
    if not isinstance(observation, Mapping):
        observation = {}

    is_incident = trigger == "incident.suspected"
    if is_incident:
        findings, unknowns, truncated = _incident_items(observation)
        assessment = observation.get("assessment")
        if assessment is None and isinstance(observation.get("ransomware_scan"), dict):
            assessment = observation["ransomware_scan"].get("assessment")
        summary = "Incident scan assessment: suspected ({} indicator(s)).".format(len(findings))
    else:
        findings, findings_truncated = _clean_items(observation.get("findings", []))
        unknowns, unknowns_truncated = _clean_items(observation.get("unknowns", []), unknown=True)
        truncated = findings_truncated or unknowns_truncated
        status = "indeterminate" if trigger == "health.indeterminate" else "unhealthy"
        summary = "Health outcome: {} ({} finding(s), {} unknown(s)).".format(
            status, len(findings), len(unknowns)
        )
        assessment = None

    if len(summary) > 200:
        summary = summary[:200]
        truncated = True
    if emitted_at is None:
        emitted_at = datetime.now(timezone.utc).isoformat()
    elif not isinstance(emitted_at, str):
        emitted_at = datetime.now(timezone.utc).isoformat()

    device, device_truncated = _pick_device(observation)
    payload = {
        "schema": SCHEMA,
        "emitted_at": emitted_at,
        "trigger": trigger,
        "summary": summary,
        "device": device,
        "findings": findings,
        "unknowns": unknowns,
    }
    if is_incident and assessment == "suspected":
        payload["assessment"] = "suspected"
    if truncated or device_truncated:
        payload["truncated"] = True

    # Defense in depth: recursively apply the project's normal redactor before
    # measuring or returning the payload. Re-apply allowlisted codes afterward
    # because the generic SID-token scrubber can rewrite long underscore codes.
    safe_findings = [{"code": item["code"], **({"severity": item["severity"]} if "severity" in item else {})} for item in findings]
    safe_unknowns = [{"code": item["code"]} for item in unknowns]
    payload = redact_value(payload)
    payload["findings"] = safe_findings
    payload["unknowns"] = safe_unknowns
    if len(_compact(payload)) <= MAX_BODY_BYTES:
        return payload

    payload["truncated"] = True
    while len(_compact(payload)) > MAX_BODY_BYTES and (payload["findings"] or payload["unknowns"]):
        if payload["findings"]:
            payload["findings"].pop()
        elif payload["unknowns"]:
            payload["unknowns"].pop()
    if len(_compact(payload)) > MAX_BODY_BYTES:
        payload["summary"] = "Notification details omitted."
    if len(_compact(payload)) > MAX_BODY_BYTES:
        payload["device"] = {}
        payload.pop("assessment", None)
    if len(_compact(payload)) > MAX_BODY_BYTES:
        # Fixed schema fields are comfortably below the cap, but retain a final
        # minimal representation if a caller supplied an enormous timestamp.
        payload = {
            "schema": SCHEMA,
            "emitted_at": datetime.now(timezone.utc).isoformat(),
            "trigger": trigger,
            "summary": "Notification details omitted.",
            "device": {}, "findings": [], "unknowns": [], "truncated": True,
        }
    return payload


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _error_kind(exc: BaseException) -> str:
    current = exc
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, (socket.timeout, TimeoutError)):
            return "timeout"
        if isinstance(current, ssl.SSLError):
            return "tls_error"
        next_value = getattr(current, "reason", None)
        current = next_value if isinstance(next_value, BaseException) else None
    return "connection_error"


def deliver_webhook(
    url: str,
    body_bytes: bytes,
    *,
    secret: Optional[str] = None,
    timeout: Optional[float] = None,
    env: Mapping[str, str] = os.environ,
    transport: Optional[Callable[..., Any]] = None,
) -> Dict[str, Any]:
    """POST JSON using verified TLS, no redirects, and no retries."""
    parsed = _url_parts(url)
    if parsed is None:
        return {"status": "rejected", "http_status": None, "error": "invalid_url"}
    try:
        if not isinstance(body_bytes, bytes):
            body_bytes = bytes(body_bytes)
    except (TypeError, ValueError):
        return {"status": "rejected", "http_status": None, "error": "invalid_body"}
    if len(body_bytes) > MAX_BODY_BYTES:
        return {"status": "rejected", "http_status": None, "error": "body_too_large"}

    if timeout is None:
        timeout_value = _timeout(env)
    else:
        try:
            timeout_value = float(timeout)
            if not math.isfinite(timeout_value):
                raise ValueError("non-finite timeout")
        except (TypeError, ValueError):
            timeout_value = 5.0
        timeout_value = max(1.0, min(10.0, timeout_value))

    request = urllib.request.Request(
        url,
        data=body_bytes,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    signing_secret = secret if secret is not None else env.get("QTS_WEBHOOK_SECRET")
    if signing_secret:
        signature = hmac.new(str(signing_secret).encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        request.add_header("X-QTS-Webhook-Signature", "sha256={}".format(signature))

    try:
        if transport is not None:
            response = transport(request, timeout=timeout_value)
        else:
            opener = urllib.request.build_opener(
                _NoRedirectHandler(),
                urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            )
            response = opener.open(request, timeout=timeout_value)
        try:
            status = response.getcode() if hasattr(response, "getcode") else getattr(response, "status", None)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
        if status is None:
            return {"status": "error", "http_status": None, "error": "missing_http_status"}
        if 200 <= int(status) < 300:
            return {"status": "delivered", "http_status": int(status), "error": None}
        if 400 <= int(status) < 500 or 300 <= int(status) < 400:
            return {"status": "rejected", "http_status": int(status), "error": "http_{}".format(int(status))}
        return {"status": "error", "http_status": int(status), "error": "http_{}".format(int(status))}
    except urllib.error.HTTPError as exc:
        status = int(exc.code) if isinstance(exc.code, int) else None
        try:
            exc.close()
        except Exception:
            pass
        if status is not None and 300 <= status < 500:
            result_status = "rejected"
        else:
            result_status = "error"
        # HTTPError.__str__ includes the request URL. Never expose that text.
        return {"status": result_status, "http_status": status, "error": "http_{}".format(status) if status is not None else "http_error"}
    except (socket.timeout, TimeoutError) as exc:
        return {"status": "error", "http_status": None, "error": "timeout"}
    except urllib.error.URLError as exc:
        return {"status": "error", "http_status": None, "error": _error_kind(exc)}
    except ssl.SSLError:
        return {"status": "error", "http_status": None, "error": "tls_error"}
    except Exception:
        # Transport adapters and unusual urllib implementations remain fail-soft.
        return {"status": "error", "http_status": None, "error": "delivery_error"}


def _env_truthy(env: Mapping[str, str], name: str) -> bool:
    return str(env.get(name, "")).strip().lower() in _TRUTHY


def _deliver_observation(trigger: Optional[str], observation: Mapping[str, Any], force: Optional[bool], env: Mapping[str, str]):
    if force is False:
        return None
    url = str(env.get("QTS_WEBHOOK_URL", "")).strip()
    if not url:
        return None
    if trigger is None:
        return {"status": "skipped", "http_status": None, "error": None}
    try:
        payload = build_payload(trigger, observation)
        body = _compact(payload)
        return deliver_webhook(url, body, secret=env.get("QTS_WEBHOOK_SECRET"), env=env)
    except Exception:
        # Notification construction is also fail-soft; do not disrupt diagnosis.
        return {"status": "error", "http_status": None, "error": "payload_error"}


def maybe_notify_health(observation: Mapping[str, Any], *, force: Optional[bool] = None, env: Mapping[str, str] = os.environ):
    """Notify for unhealthy health results, or opted-in indeterminate results."""
    if force is False:
        return None
    status = observation.get("status") if isinstance(observation, Mapping) else None
    if status == "unhealthy":
        trigger = "health.unhealthy"
    elif status == "indeterminate" and _env_truthy(env, "QTS_WEBHOOK_ON_INDETERMINATE"):
        trigger = "health.indeterminate"
    else:
        # A forced notification still uses only defined alert trigger values.
        trigger = None
    return _deliver_observation(trigger, observation if isinstance(observation, Mapping) else {}, force, env)


def maybe_notify_incident(report: Mapping[str, Any], *, force: Optional[bool] = None, env: Mapping[str, str] = os.environ):
    """Notify only for a suspected incident scan."""
    if force is False:
        return None
    assessment = report.get("assessment") if isinstance(report, Mapping) else None
    scan = report.get("ransomware_scan") if isinstance(report, Mapping) else None
    if assessment != "suspected" and isinstance(scan, dict):
        assessment = scan.get("assessment")
    trigger = "incident.suspected" if assessment == "suspected" else None
    return _deliver_observation(trigger, report if isinstance(report, Mapping) else {}, force, env)

