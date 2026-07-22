"""Core CrawlDex preflight and report helpers.

The SDK intentionally submits only the exact hosted `/api/v1/runs` fields from
the reporter SDK spec. Raw evidence artifacts never leave the process; they are
redacted, canonicalized, and hashed locally.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import logging
import math
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Sequence
from urllib import error as urllib_error
from urllib import parse, request

OUTCOMES = {
    "success",
    "success_with_handoff",
    "partial",
    "blocked",
    "failed",
    "abandoned",
}

ECHO_ACTIONS = {
    "followed",
    "overrode",
    "partial",
}

SOURCE_TIERS = {
    "seeded_example",
    "anonymous_report",
    "merchant_report",
    "attested_sdk",
    "synthetic_canary",
}

REDACTION_STATUSES = {
    "not_captured",
    "redacted",
    "hash_only",
    "private_artifact",
    "unsafe_not_submitted",
}

ATTESTATION_TYPES = {
    "none",
    "api_key",
    "signed_report",
    "local_operator",
    "canary_worker",
}

RECOMMENDATIONS = {
    "proceed_with_recipe",
    "proceed_with_guardrails",
    "use_browser_with_user_present",
    "avoid_until_fresh_evidence",
    "collect_evidence_first",
}

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
ECHO_RECORD_ID_RE = re.compile(r"^atr_[0-9a-f]{16}$")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
AGENT_KEY_RE = re.compile(r"\baa_agent_[A-Za-z0-9._-]+", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|authorization)"
    r"\s*[:=]\s*[\"']?[^\"'\s,;})]+",
    re.IGNORECASE,
)
QUERY_SECRET_RE = re.compile(
    r"([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|email)=)[^&#\s]+",
    re.IGNORECASE,
)
PAYMENT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
RESPONSE_BODY_PREVIEW_CHARS = 240
DEFAULT_API_ORIGINS = (
    "https://api.crawldex.com",
    "https://crawldex.com",
    "https://crawldex.vercel.app",
)
INSTANCE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
CHANNEL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
CHANNEL_EXACT = {"npx", "hn", "newsletter", "awi", "unknown"}
CHANNEL_PREFIXES = ("registry-", "pack-", "adapter-", "readme-", "dataset-", "web-")

DEFAULT_SENSITIVE_KEY_RE = re.compile(
    r"(password|passcode|otp|mfa|totp|cookie|cookies|authorization|auth(?:orization)?_?header|"
    r"bearer|token|api_?key|secret|csrf|session|storage|local_?storage|session_?storage|"
    r"indexeddb|screenshot|screenshots|dom|accessibility|html|body|form_?value|form_?values|"
    r"card|cvv|ssn|bank|medical|address|phone|email|email_body|download)",
    re.IGNORECASE,
)

LOGGER = logging.getLogger("crawldex_report")


class UnsafeEvidenceError(ValueError):
    """Raised when evidence is explicitly marked unsafe to submit."""


class CrawlDexNetworkError(RuntimeError):
    """Transport or HTTP error that should fail open for task execution."""


@dataclass(frozen=True)
class PreflightVerdict:
    verdict: str
    outcome_rate: Optional[float]
    blockers: tuple[str, ...]
    handoff_likelihood: str
    freshness: Mapping[str, Any]
    recommendation: Optional[str] = None
    should_attempt_autonomously: Optional[bool] = None
    risk_level: Optional[str] = None
    endpoint: Optional[str] = None
    warning: Optional[str] = None
    fail_open: bool = False
    raw: Optional[Mapping[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["blockers"] = list(self.blockers)
        return value

    def __await__(self):
        async def _self() -> "PreflightVerdict":
            return self

        return _self().__await__()


@dataclass(frozen=True)
class TrustRecordResult:
    atr_version: str
    site: str
    task: Optional[str]
    issued_at: Optional[str]
    record_id: Optional[str]
    verdict: str
    confidence: float
    accessibility: Mapping[str, Any]
    safety: Mapping[str, Any]
    freshness: Mapping[str, Any]
    task_compatibility: Mapping[str, Any]
    known_blockers: tuple[Mapping[str, Any], ...]
    user_present: Mapping[str, Any]
    agent_instruction: str
    evidence: Mapping[str, Any]
    publisher: Mapping[str, Any]
    how_to_improve: Optional[str]
    warning: Optional[str] = None
    fail_open: bool = False
    raw: Optional[Mapping[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["known_blockers"] = list(self.known_blockers)
        return value

    def __await__(self):
        async def _self() -> "TrustRecordResult":
            return self

        return _self().__await__()


@dataclass(frozen=True)
class SubmissionReceipt:
    accepted: bool
    acceptance: str
    endpoint: str
    run_id: Optional[str]
    source_tier: Optional[str]
    reporter_id: Optional[str]
    trust_level: Optional[str]
    updated_aes: Optional[float]
    payload: Mapping[str, Any]
    warning: Optional[str] = None
    fail_open: bool = False
    raw: Optional[Mapping[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __await__(self):
        async def _self() -> "SubmissionReceipt":
            return self

        return _self().__await__()


@dataclass(frozen=True)
class EchoReceipt:
    accepted: bool
    endpoint: str
    payload: Optional[Mapping[str, Any]]
    warning: Optional[str] = None
    fail_open: bool = False
    skipped: bool = False
    raw: Optional[Mapping[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __await__(self):
        async def _self() -> "EchoReceipt":
            return self

        return _self().__await__()


class CrawlDexReporter:
    def __init__(
        self,
        report_url: Optional[str] = None,
        echo_url: Optional[str] = None,
        agent_key: Optional[str] = None,
        ingest_token: Optional[str] = None,
        dry_run: bool = False,
        *,
        timeout: float = 10.0,
        preflight_url: Optional[str] = None,
        trust_record_url: Optional[str] = None,
        api_origin: Optional[str] = None,
        auto_report: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.report_url = _clean_optional(report_url) or _clean_optional(os.getenv("CRAWLDEX_REPORT_URL"))
        self.echo_url = _clean_optional(echo_url)
        self.agent_key = _clean_optional(agent_key) or _clean_optional(os.getenv("CRAWLDEX_AGENT_KEY"))
        self.ingest_token = _clean_optional(ingest_token) or _clean_optional(os.getenv("CRAWLDEX_INGEST_TOKEN"))
        self.dry_run = bool(dry_run)
        self.timeout = timeout
        self.preflight_url = _clean_optional(preflight_url) or _clean_optional(os.getenv("CRAWLDEX_PREFLIGHT_URL"))
        self.trust_record_url = _clean_optional(trust_record_url) or _clean_optional(os.getenv("CRAWLDEX_TRUST_RECORD_URL"))
        self.api_origin = _clean_optional(api_origin) or _clean_optional(os.getenv("CRAWLDEX_API_ORIGIN"))
        self.auto_report = bool(auto_report)
        self._logger = logger or LOGGER

    def preflight(
        self,
        site: str,
        task: str,
        *,
        agent_profile: Optional[Mapping[str, Any]] = None,
        intent: Optional[str] = None,
        constraints: Optional[Mapping[str, Any]] = None,
    ) -> PreflightVerdict:
        payload: Dict[str, Any] = {
            "site": validate_text("site", site, 253),
            "task": validate_text("task", task, 160),
        }
        mapped_profile = map_agent_profile(agent_profile)
        if mapped_profile:
            payload["agent_profile"] = mapped_profile
        if intent is not None:
            payload["intent"] = validate_text("intent", intent, 500)
        if constraints is not None:
            if not isinstance(constraints, Mapping):
                raise ValueError("constraints must be a mapping.")
            payload["constraints"] = dict(constraints)

        endpoints = derive_preflight_urls(self.preflight_url, self.report_url, self.api_origin)
        if not endpoints:
            return self._fail_open_preflight(
                "CrawlDex preflight skipped: report_url/CRAWLDEX_REPORT_URL is not configured.",
                "",
            )

        try:
            endpoint, body = self._post_json_with_fallback(endpoints, payload)
        except CrawlDexNetworkError as exc:
            return self._fail_open_preflight(f"CrawlDex preflight failed open: {exc}", endpoints[0])

        try:
            return preflight_verdict_from_response(body, endpoint)
        except (TypeError, ValueError) as exc:
            return self._fail_open_preflight(f"CrawlDex preflight failed open: invalid response: {exc}", endpoint)

    def trust_record(self, site: str, task: Optional[str] = None) -> TrustRecordResult:
        clean_site = validate_text("site", site, 253)
        clean_task = validate_text("task", task, 160) if task is not None else None
        endpoints = derive_trust_record_urls(self.trust_record_url, self.api_origin, self.report_url, clean_site, clean_task)
        if self.dry_run:
            return self._fail_open_trust_record(clean_site, clean_task, "CrawlDex trust_record skipped: dry_run is enabled.")
        if not endpoints:
            return self._fail_open_trust_record(
                clean_site,
                clean_task,
                "CrawlDex trust_record skipped: trust_record_url, api_origin, report_url, or CRAWLDEX_API_ORIGIN is not configured.",
            )

        try:
            _endpoint, body = self._get_json_with_fallback(endpoints, timeout=min(self.timeout, 5.0), include_auth=True)
        except CrawlDexNetworkError as exc:
            return self._fail_open_trust_record(clean_site, clean_task, f"CrawlDex trust_record failed open: {exc}")

        try:
            return trust_record_from_response(body)
        except (TypeError, ValueError) as exc:
            return self._fail_open_trust_record(clean_site, clean_task, f"CrawlDex trust_record failed open: invalid response: {exc}")

    def trustRecord(self, site: str, task: Optional[str] = None) -> TrustRecordResult:
        return self.trust_record(site, task)

    def report(self, input_data: Mapping[str, Any]) -> SubmissionReceipt:
        try:
            payload = map_to_run_report(input_data)
        except UnsafeEvidenceError as exc:
            return self._fail_open_report(str(exc), {}, self.report_url or "")

        endpoints = derive_report_urls(self.report_url, self.api_origin)
        endpoint = endpoints[0] if endpoints else ""
        if not endpoints:
            return self._fail_open_report(
                "CrawlDex report skipped: report_url/CRAWLDEX_REPORT_URL is not configured.",
                payload,
                "",
            )

        if self.dry_run:
            return SubmissionReceipt(
                accepted=True,
                acceptance="dry_run",
                endpoint=endpoint,
                run_id=None,
                source_tier=payload.get("source_tier"),
                reporter_id=None,
                trust_level=None,
                updated_aes=None,
                payload=payload,
            )

        try:
            endpoint, body = self._post_json_with_fallback(endpoints, payload)
        except CrawlDexNetworkError as exc:
            return self._fail_open_report(f"CrawlDex report failed open: {exc}", payload, endpoint)

        receipt = receipt_from_response(endpoint, payload, body)
        self._maybe_auto_echo(input_data, receipt)
        return receipt

    def report_outcome(self, input_data: Mapping[str, Any]) -> SubmissionReceipt:
        return self.report(input_data)

    def echo(
        self,
        record_id: str,
        action: str,
        task_attempted: bool = True,
        removed_in_batch: Optional[bool] = None,
    ) -> EchoReceipt:
        payload = build_echo_payload(record_id, action, task_attempted, removed_in_batch)
        endpoints = derive_echo_urls(self.echo_url, self.api_origin, self.report_url)
        endpoint = endpoints[0] if endpoints else ""

        if self.dry_run:
            return EchoReceipt(
                accepted=False,
                endpoint=endpoint,
                payload=payload,
                warning="CrawlDex echo skipped: dry_run is enabled.",
                skipped=True,
            )

        if not endpoints:
            return self._fail_open_echo(
                "CrawlDex echo skipped: echo_url, api_origin, report_url, or CRAWLDEX_API_ORIGIN is not configured.",
                "",
                payload,
            )

        try:
            endpoint, body = self._post_json_with_fallback(endpoints, payload, timeout=min(self.timeout, 5.0), include_auth=True)
        except CrawlDexNetworkError as exc:
            return self._fail_open_echo(f"CrawlDex echo failed open: {exc}", endpoint, payload)

        return EchoReceipt(
            accepted=True,
            endpoint=endpoint,
            payload=payload,
            raw=body,
        )

    def echo_record(
        self,
        record_id: str,
        action: str,
        task_attempted: bool = True,
        removed_in_batch: Optional[bool] = None,
    ) -> EchoReceipt:
        return self.echo(record_id, action, task_attempted, removed_in_batch)

    def map_to_run_report(self, input_data: Mapping[str, Any]) -> Dict[str, Any]:
        return map_to_run_report(input_data)

    def _maybe_auto_echo(self, input_data: Mapping[str, Any], receipt: SubmissionReceipt) -> None:
        if not self.auto_report or not receipt.accepted:
            return
        record_id = receipt.payload.get("record_id")
        if not record_id:
            return
        action = input_data.get("echo_action") or input_data.get("echoAction") or "followed"
        task_attempted = input_data.get("task_attempted", input_data.get("taskAttempted", True))
        removed_in_batch = input_data.get("removed_in_batch", input_data.get("removedInBatch"))
        try:
            self.echo(str(record_id), str(action), bool(task_attempted), removed_in_batch)
        except ValueError as exc:
            self._logger.warning("CrawlDex auto_report echo skipped: %s", exc)

    def _post_json(
        self,
        endpoint: str,
        payload: Mapping[str, Any],
        *,
        timeout: Optional[float] = None,
        include_auth: bool = True,
    ) -> Mapping[str, Any]:
        _endpoint, body = self._post_json_with_fallback([endpoint], payload, timeout=timeout, include_auth=include_auth)
        return body

    def _post_json_with_fallback(
        self,
        endpoints: Sequence[str],
        payload: Mapping[str, Any],
        *,
        timeout: Optional[float] = None,
        include_auth: bool = True,
    ) -> tuple[str, Mapping[str, Any]]:
        return self._request_json_with_fallback("POST", endpoints, payload, timeout=timeout, include_auth=include_auth)

    def _get_json_with_fallback(
        self,
        endpoints: Sequence[str],
        *,
        timeout: float,
        include_auth: bool = False,
    ) -> tuple[str, Mapping[str, Any]]:
        return self._request_json_with_fallback("GET", endpoints, None, timeout=timeout, include_auth=include_auth)

    def _request_json_with_fallback(
        self,
        method: str,
        endpoints: Sequence[str],
        payload: Optional[Mapping[str, Any]],
        *,
        timeout: Optional[float] = None,
        include_auth: bool = True,
    ) -> tuple[str, Mapping[str, Any]]:
        if not endpoints:
            raise CrawlDexNetworkError("no endpoints configured")

        deadline_seconds = timeout if timeout is not None else self.timeout
        deadline = time.monotonic() + max(deadline_seconds, 0)
        last_error: Optional[BaseException] = None

        for index, endpoint in enumerate(endpoints):
            remaining = deadline - time.monotonic() if deadline_seconds > 0 else deadline_seconds
            if deadline_seconds > 0 and remaining <= 0:
                raise CrawlDexNetworkError(f"timed out after {deadline_seconds:.1f}s")
            try:
                return endpoint, self._request_json(method, endpoint, payload, timeout=remaining, include_auth=include_auth)
            except CrawlDexNetworkError as exc:
                last_error = exc
                if not is_retryable_network_error(exc) or index == len(endpoints) - 1:
                    raise

        if last_error:
            raise CrawlDexNetworkError(str(last_error)) from last_error
        raise CrawlDexNetworkError("request failed")

    def _request_json(
        self,
        method: str,
        endpoint: str,
        payload: Optional[Mapping[str, Any]],
        *,
        timeout: Optional[float],
        include_auth: bool,
    ) -> Mapping[str, Any]:
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "crawldex-report-py/0.3.0",
        }
        headers.update(crawldex_client_headers())
        if method == "POST":
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload or {}, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if include_auth:
            headers.update(self._auth_headers())
        req = request.Request(endpoint, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout if timeout is not None else self.timeout) as response:
                status = getattr(response, "status", 200)
                content_type = response.headers.get("Content-Type", "")
                raw = response.read().decode("utf-8")
                if not is_json_content_type(content_type):
                    raise CrawlDexNetworkError(
                        f"HTTP {status}: non-JSON response ({content_type or 'missing content-type'}): {truncate_raw_body(raw)}"
                    )
        except urllib_error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            if is_challenge_http_error(exc.code, exc.headers, raw):
                raise CrawlDexNetworkError(f"retryable challenge response from {endpoint}") from exc
            body = None
            content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
            if is_json_content_type(content_type):
                try:
                    body = parse_json(raw)
                except json.JSONDecodeError:
                    body = None
            raise CrawlDexNetworkError(f"HTTP {exc.code}: {error_message(body, raw)}") from exc
        except (urllib_error.URLError, TimeoutError, OSError) as exc:
            raise CrawlDexNetworkError(str(exc)) from exc

        try:
            body = parse_json(raw)
        except json.JSONDecodeError as exc:
            raise CrawlDexNetworkError(f"HTTP {status}: invalid JSON response: {truncate_raw_body(raw)}") from exc
        if not isinstance(body, Mapping):
            raise CrawlDexNetworkError(f"HTTP {status}: JSON response body is not an object")
        return body

    def _get_json(self, endpoint: str, *, timeout: float) -> Mapping[str, Any]:
        _endpoint, body = self._get_json_with_fallback([endpoint], timeout=timeout)
        return body

    def _auth_headers(self) -> Dict[str, str]:
        if self.agent_key:
            return {"x-crawldex-agent-key": self.agent_key}
        if self.ingest_token:
            return {"x-crawldex-ingest-token": self.ingest_token}
        return {}

    def _fail_open_preflight(self, warning: str, endpoint: str) -> PreflightVerdict:
        self._logger.warning(warning)
        return PreflightVerdict(
            verdict="unavailable",
            outcome_rate=None,
            blockers=(),
            handoff_likelihood="unknown",
            freshness=unknown_freshness(),
            endpoint=endpoint,
            warning=warning,
            fail_open=True,
            raw=None,
        )

    def _fail_open_trust_record(self, site: str, task: Optional[str], warning: str) -> TrustRecordResult:
        self._logger.warning(warning)
        return TrustRecordResult(
            atr_version="0.1",
            site=site,
            task=task,
            issued_at=None,
            record_id=None,
            verdict="unknown",
            confidence=0.0,
            accessibility={
                "reachable": "unknown",
                "agent_hostility": "unknown",
                "success_rate": "unknown",
                "handoff_rate": "unknown",
                "blocked_rate": "unknown",
                "n": 0,
                "last_verified": None,
            },
            safety={
                "canonical": "unknown",
                "canonical_alternative": None,
                "domain_risk": "unknown",
                "notes": [],
            },
            freshness={
                "median_evidence_age_days": None,
                "surface_last_changed": None,
                "stale": "unknown",
            },
            task_compatibility={
                "supported": "unknown",
                "expected_steps": "unknown",
                "recipe_available": False,
                "alternatives": [],
            },
            known_blockers=(),
            user_present={
                "required": "unknown",
                "reasons": [],
                "irreversible_action": "unknown",
            },
            agent_instruction="CrawlDex trust record unavailable. Fail open for caller control, but treat the site-task as unknown and use caution before acting.",
            evidence={
                "sources": {},
                "canonical_url": "",
                "dispute_url": "",
            },
            publisher={
                "claimed": False,
                "statement": None,
            },
            how_to_improve=None,
            warning=warning,
            fail_open=True,
            raw=None,
        )

    def _fail_open_report(
        self,
        warning: str,
        payload: Mapping[str, Any],
        endpoint: str,
    ) -> SubmissionReceipt:
        self._logger.warning(warning)
        return SubmissionReceipt(
            accepted=False,
            acceptance="fail_open",
            endpoint=endpoint,
            run_id=None,
            source_tier=payload.get("source_tier") if isinstance(payload, Mapping) else None,
            reporter_id=None,
            trust_level=None,
            updated_aes=None,
            payload=payload,
            warning=warning,
            fail_open=True,
        )

    def _fail_open_echo(
        self,
        warning: str,
        endpoint: str,
        payload: Mapping[str, Any],
    ) -> EchoReceipt:
        self._logger.warning(warning)
        return EchoReceipt(
            accepted=False,
            endpoint=endpoint,
            payload=payload,
            warning=warning,
            fail_open=True,
        )


def crawldex_client_headers(env: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    source = env if env is not None else os.environ
    headers: Dict[str, str] = {}
    instance_id = read_or_create_instance_id(source)
    if instance_id:
        headers["x-crawldex-instance"] = instance_id
    channel = crawldex_channel(source)
    if channel:
        headers["x-crawldex-channel"] = channel
    return headers


def read_or_create_instance_id(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    source = env if env is not None else os.environ
    if source.get("CRAWLDEX_NO_INSTANCE_ID") == "1":
        return None

    file_path = instance_id_path(source)
    if file_path is None:
        return None

    try:
        existing = file_path.read_text(encoding="utf-8").strip()
        if INSTANCE_ID_RE.match(existing):
            return existing.lower()
    except OSError:
        pass

    next_id = str(uuid.uuid4())
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(f"{next_id}\n", encoding="utf-8")
        try:
            file_path.chmod(0o600)
        except OSError:
            pass
        return next_id
    except OSError:
        return None


def instance_id_path(env: Optional[Mapping[str, str]] = None) -> Optional[Path]:
    source = env if env is not None else os.environ
    if os.name == "nt":
        app_data = _clean_optional(source.get("APPDATA"))
        return Path(app_data) / "crawldex" / "instance-id" if app_data else None

    config_root = _clean_optional(source.get("XDG_CONFIG_HOME"))
    if not config_root:
        home = _clean_optional(source.get("HOME"))
        config_root = str(Path(home) / ".config") if home else str(Path.home() / ".config")
    return Path(config_root) / "crawldex" / "instance-id"


def crawldex_channel(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    source = env if env is not None else os.environ
    channel = _clean_optional(source.get("CRAWLDEX_CHANNEL"))
    if not channel:
        return None
    normalized = channel.lower()
    if not CHANNEL_RE.match(normalized):
        return None
    if normalized in CHANNEL_EXACT or any(normalized.startswith(prefix) for prefix in CHANNEL_PREFIXES):
        return normalized
    return None


def map_to_run_report(input_data: Mapping[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_data, Mapping):
        raise ValueError("report input must be a mapping.")

    payload: Dict[str, Any] = {
        "site": validate_text("site", required(input_data, "site"), 253),
        "task": validate_text("task", required(input_data, "task"), 160),
        "outcome": validate_enum("outcome", required(input_data, "outcome"), OUTCOMES),
    }

    record_id = aliased_value(input_data, "record_id", "recordId")
    if record_id is not None:
        payload["record_id"] = validate_record_id(record_id)

    agent_profile = map_agent_profile(input_data.get("agent_profile"))
    if agent_profile:
        payload["agent_profile"] = agent_profile

    friction = map_text_list(input_data.get("friction"), "friction", 128, max_items=50)
    if friction:
        payload["friction"] = friction

    if "steps" in input_data and input_data["steps"] is not None:
        steps = input_data["steps"]
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 0:
            raise ValueError("steps must be a non-negative integer.")
        payload["steps"] = steps

    set_number(payload, "duration_sec", input_data.get("duration_sec"))
    set_number(payload, "token_cost_usd", input_data.get("token_cost_usd"))
    set_number(payload, "access_fee_usd", input_data.get("access_fee_usd"))

    if input_data.get("source_tier") is not None:
        payload["source_tier"] = validate_enum("source_tier", input_data["source_tier"], SOURCE_TIERS)

    evidence = map_evidence(input_data.get("evidence"), payload)
    if evidence:
        payload["evidence"] = evidence

    reporter = map_reporter(input_data.get("reporter"))
    if reporter:
        payload["reporter"] = reporter

    if input_data.get("occurred_at") is not None:
        occurred_at = validate_text("occurred_at", input_data["occurred_at"], 80)
        validate_iso_datetime("occurred_at", occurred_at)
        payload["occurred_at"] = occurred_at

    return payload


def echo(
    record_id: str,
    action: str,
    *,
    task_attempted: bool = True,
    removed_in_batch: Optional[bool] = None,
    report_url: Optional[str] = None,
    echo_url: Optional[str] = None,
    api_origin: Optional[str] = None,
    timeout: float = 10.0,
    dry_run: bool = False,
) -> EchoReceipt:
    return CrawlDexReporter(
        report_url=report_url,
        echo_url=echo_url,
        api_origin=api_origin,
        timeout=timeout,
        dry_run=dry_run,
    ).echo(record_id, action, task_attempted, removed_in_batch)


def build_echo_payload(
    record_id: str,
    action: str,
    task_attempted: bool = True,
    removed_in_batch: Optional[bool] = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "record_id": validate_record_id(record_id),
        "action_taken": validate_enum("action", action, ECHO_ACTIONS),
        "task_attempted": bool(task_attempted),
    }
    if removed_in_batch is not None:
        if not isinstance(removed_in_batch, bool):
            raise ValueError("removed_in_batch must be a boolean when provided.")
        payload["removed_in_batch"] = removed_in_batch
    return payload


def map_agent_profile(input_data: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if input_data is None:
        return None
    if not isinstance(input_data, Mapping):
        raise ValueError("agent_profile must be a mapping.")

    profile: Dict[str, Any] = {}
    for key in ("stack", "model", "browser_runtime", "version", "identity_class"):
        if input_data.get(key) is not None:
            profile[key] = validate_text(f"agent_profile.{key}", input_data[key], 128)

    capabilities = input_data.get("capabilities")
    if capabilities is not None:
        if not isinstance(capabilities, Mapping):
            raise ValueError("agent_profile.capabilities must be a mapping.")
        mapped: Dict[str, Any] = {}
        for raw_key, raw_value in capabilities.items():
            clean_key = validate_text("agent_profile.capabilities key", raw_key, 128)
            if isinstance(raw_value, bool):
                mapped[clean_key] = raw_value
            elif isinstance(raw_value, str):
                mapped[clean_key] = validate_text(f"agent_profile.capabilities.{clean_key}", raw_value, 128)
            elif isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
                validate_non_negative_number(f"agent_profile.capabilities.{clean_key}", raw_value)
                mapped[clean_key] = raw_value
            else:
                raise ValueError(f"agent_profile.capabilities.{clean_key} must be a boolean, number, or string.")
        if mapped:
            profile["capabilities"] = mapped

    return profile or None


def map_evidence(
    input_data: Any,
    payload: MutableMapping[str, Any],
) -> Optional[Dict[str, Any]]:
    if input_data is None:
        return None
    if not isinstance(input_data, Mapping):
        raise ValueError("evidence must be a mapping.")

    redaction_status = input_data.get("redaction_status")
    if redaction_status is not None:
        redaction_status = validate_enum("evidence.redaction_status", redaction_status, REDACTION_STATUSES)
        if redaction_status == "unsafe_not_submitted":
            raise UnsafeEvidenceError("CrawlDex report not submitted: evidence.redaction_status is unsafe_not_submitted.")
        profile = payload.setdefault("agent_profile", {})
        capabilities = profile.setdefault("capabilities", {})
        capabilities["evidence_redaction"] = redaction_status

    evidence: Dict[str, Any] = {}
    for key, max_length in (("id", 128), ("uri", 2048), ("signature", 4096)):
        if input_data.get(key) is not None:
            evidence[key] = validate_text(f"evidence.{key}", input_data[key], max_length)

    if "uri" not in evidence and input_data.get("artifact_path") is not None:
        evidence["uri"] = validate_text("evidence.artifact_path", input_data["artifact_path"], 2048)

    artifact_types = map_text_list(input_data.get("artifact_types"), "evidence.artifact_types", 128, max_items=20)
    if artifact_types:
        evidence["artifact_types"] = artifact_types

    if "artifact" in input_data:
        redacted = redact_evidence_artifact(
            input_data["artifact"],
            {"redaction_status": redaction_status or "hash_only"},
        )
        generated_hash = hash_evidence_artifact(redacted)
        supplied_hash = input_data.get("hash")
        if supplied_hash is not None and supplied_hash != generated_hash:
            raise ValueError("evidence.hash does not match the redacted evidence artifact hash.")
        evidence["hash"] = generated_hash
    elif input_data.get("hash") is not None:
        evidence["hash"] = validate_text("evidence.hash", input_data["hash"], 128)

    return evidence or None


def map_reporter(input_data: Any) -> Optional[Dict[str, Any]]:
    if input_data is None:
        return None
    if not isinstance(input_data, Mapping):
        raise ValueError("reporter must be a mapping.")

    reporter: Dict[str, Any] = {}
    for key, max_length in (("id", 128), ("public_key_id", 128), ("signature", 4096)):
        if input_data.get(key) is not None:
            reporter[key] = validate_text(f"reporter.{key}", input_data[key], max_length)
    if input_data.get("attestation_type") is not None:
        reporter["attestation_type"] = validate_enum(
            "reporter.attestation_type",
            input_data["attestation_type"],
            ATTESTATION_TYPES,
        )
    return reporter or None


def hash_evidence_artifact(artifact: Any) -> str:
    if isinstance(artifact, str):
        payload = artifact.encode("utf-8")
    elif isinstance(artifact, (bytes, bytearray, memoryview)):
        payload = bytes(artifact)
    else:
        payload = canonical_json(artifact).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def canonical_json(value: Any) -> str:
    canonical = canonicalize(value, set())
    return json.dumps(canonical, ensure_ascii=False, separators=(",", ":"))


def canonicalize(value: Any, seen: set[int]) -> Any:
    if value is None or isinstance(value, str) or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Evidence artifacts cannot contain non-finite numbers.")
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise ValueError("Binary values are only supported as the top-level artifact passed to hash_evidence_artifact.")
    if isinstance(value, list):
        obj_id = id(value)
        if obj_id in seen:
            raise ValueError("Evidence artifacts cannot contain circular references.")
        seen.add(obj_id)
        result = [canonicalize(item, seen) for item in value]
        seen.remove(obj_id)
        return result
    if isinstance(value, Mapping):
        obj_id = id(value)
        if obj_id in seen:
            raise ValueError("Evidence artifacts cannot contain circular references.")
        seen.add(obj_id)
        result: Dict[str, Any] = {}
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise ValueError("Evidence artifact object keys must be strings.")
            result[key] = canonicalize(value[key], seen)
        seen.remove(obj_id)
        return result
    raise ValueError("Evidence artifacts must be finite JSON-compatible values.")


def redact_evidence_artifact(
    artifact: Any,
    policy: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    policy = policy or {}
    status = policy.get("redaction_status", policy.get("redactionStatus", "hash_only"))
    if status == "unsafe_not_submitted":
        raise UnsafeEvidenceError("CrawlDex evidence redaction_status is unsafe_not_submitted.")
    if status not in REDACTION_STATUSES:
        raise ValueError("redaction_status must be a known CrawlDex redaction status.")

    pattern = policy.get("sensitive_key_pattern")
    if pattern is None:
        sensitive_key_re = DEFAULT_SENSITIVE_KEY_RE
    elif isinstance(pattern, str):
        sensitive_key_re = re.compile(pattern, re.IGNORECASE)
    else:
        sensitive_key_re = pattern

    removed: set[str] = set()
    redacted = redact_value(artifact, "$", removed, sensitive_key_re)
    return {
        "schema": "crawldex.evidence.redacted.v1",
        "redaction_status": status,
        "artifact": redacted,
        "removed_fields": sorted(removed),
    }


def redact_value(value: Any, path: str, removed: set[str], sensitive_key_re: re.Pattern[str]) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        redacted, changed = redact_string(value)
        if changed:
            removed.add(path)
        return redacted
    if isinstance(value, list):
        return [redact_value(item, f"{path}[{index}]", removed, sensitive_key_re) for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        output: Dict[str, Any] = {}
        for raw_key, child in value.items():
            if not isinstance(raw_key, str):
                removed.add(path)
                continue
            child_path = f"{path}.{raw_key}"
            if sensitive_key_re.search(raw_key):
                removed.add(child_path)
                output[raw_key] = "[redacted]"
            else:
                output[raw_key] = redact_value(child, child_path, removed, sensitive_key_re)
        return output
    removed.add(path)
    return "[redacted]"


def redact_string(value: str) -> tuple[str, bool]:
    redacted = URL_RE.sub(strip_url_query, value)
    redacted = QUERY_SECRET_RE.sub(r"\1[redacted]", redacted)
    redacted = EMAIL_RE.sub("[redacted-email]", redacted)
    redacted = BEARER_RE.sub("Bearer [redacted-token]", redacted)
    redacted = AGENT_KEY_RE.sub("aa_agent_[redacted]", redacted)
    redacted = JWT_RE.sub("[redacted-token]", redacted)
    redacted = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
    redacted = PAYMENT_CARD_RE.sub("[redacted-card]", redacted)
    redacted = strip_control_chars(redacted)
    return redacted, redacted != value


def strip_url_query(match: re.Match[str]) -> str:
    value = match.group(0)
    suffix = ""
    while value and value[-1] in ".,);]":
        suffix = value[-1] + suffix
        value = value[:-1]
    parsed = parse.urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return match.group(0)
    clean = parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    return clean + suffix


def preflight_verdict_from_response(body: Mapping[str, Any], endpoint: str) -> PreflightVerdict:
    decision = body.get("decision") if isinstance(body.get("decision"), Mapping) else {}
    score = body.get("score") if isinstance(body.get("score"), Mapping) else {}
    recommendation = decision.get("recommendation") if isinstance(decision.get("recommendation"), str) else None
    verdict = recommendation if recommendation in RECOMMENDATIONS else "unavailable"
    blockers = tuple(map_text_list(score.get("known_blockers"), "known_blockers", 128, max_items=50) or [])
    freshness = body.get("freshness") or score.get("freshness") or unknown_freshness()
    if not isinstance(freshness, Mapping):
        freshness = unknown_freshness()
    outcome_rate = score.get("outcome_rate")
    if outcome_rate is not None:
        validate_non_negative_number("outcome_rate", outcome_rate)
        if outcome_rate > 1:
            raise ValueError("outcome_rate must be between 0 and 1.")

    risk_level = decision.get("risk_level") if isinstance(decision.get("risk_level"), str) else None
    should_attempt = decision.get("should_attempt_autonomously")
    if not isinstance(should_attempt, bool):
        should_attempt = None

    return PreflightVerdict(
        verdict=verdict,
        outcome_rate=outcome_rate,
        blockers=blockers,
        handoff_likelihood=derive_handoff_likelihood(verdict, risk_level, should_attempt, blockers),
        freshness=dict(freshness),
        recommendation=recommendation,
        should_attempt_autonomously=should_attempt,
        risk_level=risk_level,
        endpoint=endpoint,
        raw=body,
    )


def trust_record_from_response(body: Mapping[str, Any]) -> TrustRecordResult:
    required = [
        "atr_version",
        "site",
        "task",
        "issued_at",
        "record_id",
        "verdict",
        "confidence",
        "accessibility",
        "safety",
        "freshness",
        "task_compatibility",
        "known_blockers",
        "user_present",
        "agent_instruction",
        "evidence",
        "publisher",
        "how_to_improve",
    ]
    for key in required:
        if key not in body:
            raise ValueError(f"{key} is required.")
    if body["atr_version"] != "0.1":
        raise ValueError("atr_version must be 0.1.")
    if body["verdict"] not in {"proceed", "proceed_with_guardrails", "handoff_required", "user_needed", "avoid", "unknown"}:
        raise ValueError("verdict must be a known ATR verdict.")
    confidence = body["confidence"]
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or confidence < 0 or confidence > 1:
        raise ValueError("confidence must be between 0 and 1.")
    for key in ("accessibility", "safety", "freshness", "task_compatibility", "user_present", "evidence", "publisher"):
        if not isinstance(body[key], Mapping):
            raise ValueError(f"{key} must be an object.")
    blockers = body["known_blockers"]
    if not isinstance(blockers, Sequence) or isinstance(blockers, (str, bytes, bytearray)):
        raise ValueError("known_blockers must be an array.")
    if any(not isinstance(blocker, Mapping) for blocker in blockers):
        raise ValueError("known_blockers entries must be objects.")

    return TrustRecordResult(
        atr_version="0.1",
        site=validate_text("site", body["site"], 253),
        task=validate_text("task", body["task"], 160) if body["task"] is not None else None,
        issued_at=validate_text("issued_at", body["issued_at"], 80),
        record_id=validate_text("record_id", body["record_id"], 128),
        verdict=str(body["verdict"]),
        confidence=float(confidence),
        accessibility=dict(body["accessibility"]),
        safety=dict(body["safety"]),
        freshness=dict(body["freshness"]),
        task_compatibility=dict(body["task_compatibility"]),
        known_blockers=tuple(dict(blocker) for blocker in blockers),
        user_present=dict(body["user_present"]),
        agent_instruction=validate_text("agent_instruction", body["agent_instruction"], 2000),
        evidence=dict(body["evidence"]),
        publisher=dict(body["publisher"]),
        how_to_improve=validate_text("how_to_improve", body["how_to_improve"], 1000) if body["how_to_improve"] is not None else None,
        raw=body,
    )


def receipt_from_response(endpoint: str, payload: Mapping[str, Any], body: Mapping[str, Any]) -> SubmissionReceipt:
    if body.get("accepted") is False:
        message = str(body.get("message") or body.get("reason") or "CrawlDex rejected report.")
        return SubmissionReceipt(
            accepted=False,
            acceptance="fail_open",
            endpoint=endpoint,
            run_id=None,
            source_tier=payload.get("source_tier"),
            reporter_id=None,
            trust_level=None,
            updated_aes=None,
            payload=payload,
            warning=message,
            fail_open=True,
            raw=body,
        )

    run = body.get("run") if isinstance(body.get("run"), Mapping) else {}
    reporter = run.get("reporter") if isinstance(run.get("reporter"), Mapping) else {}
    trust = run.get("trust") if isinstance(run.get("trust"), Mapping) else body.get("trust")
    trust_level = trust.get("level") if isinstance(trust, Mapping) and isinstance(trust.get("level"), str) else None
    updated_status = body.get("updated_status") if isinstance(body.get("updated_status"), Mapping) else {}
    source_tier = run.get("source_tier") if isinstance(run.get("source_tier"), str) else None
    acceptance = "trusted" if source_tier in {"attested_sdk", "synthetic_canary"} else "anonymous"
    return SubmissionReceipt(
        accepted=True,
        acceptance=acceptance,
        endpoint=endpoint,
        run_id=run.get("id") if isinstance(run.get("id"), str) else None,
        source_tier=source_tier,
        reporter_id=reporter.get("id") if isinstance(reporter.get("id"), str) else None,
        trust_level=trust_level,
        updated_aes=updated_status.get("aes") if isinstance(updated_status.get("aes"), (int, float)) else None,
        payload=payload,
        raw=body,
    )


def derive_handoff_likelihood(
    verdict: str,
    risk_level: Optional[str],
    should_attempt: Optional[bool],
    blockers: Iterable[str],
) -> str:
    blocker_text = " ".join(blockers)
    if verdict == "use_browser_with_user_present":
        return "high"
    if re.search(r"(login|auth|mfa|2fa|payment|identity|user_present|handoff|upload|final)", blocker_text):
        return "high"
    if should_attempt is False and verdict in {"avoid_until_fresh_evidence", "collect_evidence_first"}:
        return "unknown"
    if risk_level == "high":
        return "high"
    if risk_level == "medium":
        return "medium"
    if risk_level == "low":
        return "low"
    return "unknown"


def derive_report_urls(report_url: Optional[str], api_origin: Optional[str]) -> list[str]:
    if report_url:
        return [report_url]
    return endpoint_candidates(api_origin_candidates(api_origin, None), "/api/v1/runs")


def derive_preflight_urls(
    preflight_url: Optional[str],
    report_url: Optional[str],
    api_origin: Optional[str],
) -> list[str]:
    if preflight_url:
        return [preflight_url]
    if report_url:
        endpoint = derive_preflight_url(report_url)
        return [endpoint] if endpoint else []
    return endpoint_candidates(api_origin_candidates(api_origin, None), "/api/v1/preflight")


def derive_preflight_url(report_url: Optional[str]) -> Optional[str]:
    if not report_url:
        return None
    parsed = parse.urlsplit(report_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path.rstrip("/")
    if path.endswith("/api/v1/runs"):
        preflight_path = path[: -len("/runs")] + "/preflight"
    else:
        preflight_path = "/api/v1/preflight"
    return parse.urlunsplit((parsed.scheme, parsed.netloc, preflight_path, "", ""))


def derive_trust_record_urls(
    trust_record_url: Optional[str],
    api_origin: Optional[str],
    report_url: Optional[str],
    site: str,
    task: Optional[str],
) -> list[str]:
    suffix = parse.quote(site, safe="")
    if task:
        suffix += "/" + parse.quote(task, safe="")

    if trust_record_url:
        endpoint = normalize_trust_record_url(trust_record_url, suffix)
        return [endpoint] if endpoint else []

    return endpoint_candidates(api_origin_candidates(api_origin, report_url), f"/api/v1/trust-record/{suffix}")


def derive_trust_record_url(
    trust_record_url: Optional[str],
    api_origin: Optional[str],
    report_url: Optional[str],
    site: str,
    task: Optional[str],
) -> Optional[str]:
    return next(iter(derive_trust_record_urls(trust_record_url, api_origin, report_url, site, task)), None)


def derive_echo_urls(
    echo_url: Optional[str],
    api_origin: Optional[str],
    report_url: Optional[str],
) -> list[str]:
    if echo_url:
        endpoint = normalize_endpoint_path(echo_url, "/api/v1/echo")
        return [endpoint] if endpoint else []
    return endpoint_candidates(api_origin_candidates(api_origin, report_url), "/api/v1/echo")


def derive_echo_url(
    echo_url: Optional[str],
    api_origin: Optional[str],
    report_url: Optional[str],
) -> Optional[str]:
    return next(iter(derive_echo_urls(echo_url, api_origin, report_url)), None)


def normalize_trust_record_url(endpoint: str, suffix: str) -> Optional[str]:
    parsed = parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path.rstrip("/")
    if path.endswith("/api/v1/trust-record"):
        path = f"{path}/{suffix}"
    elif "/api/v1/trust-record/" not in path:
        path = f"/api/v1/trust-record/{suffix}"
    return parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def normalize_endpoint_path(endpoint: str, path: str) -> Optional[str]:
    parsed = parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def api_origin_candidates(api_origin: Optional[str], report_url: Optional[str]) -> list[str]:
    configured = normalize_origin(api_origin) or origin_from_endpoint(report_url)
    defaults = [origin for origin in (normalize_origin(value) for value in DEFAULT_API_ORIGINS) if origin]
    if configured:
        return [configured, *[origin for origin in defaults if origin != configured]]
    return defaults


def endpoint_candidates(origins: Sequence[str], path: str) -> list[str]:
    endpoints: list[str] = []
    for origin in origins:
        parsed = parse.urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        endpoints.append(parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", "")))
    return endpoints


def normalize_origin(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    parsed = parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def origin_from_endpoint(endpoint: Optional[str]) -> Optional[str]:
    if not endpoint:
        return None
    parsed = parse.urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def is_retryable_network_error(exc: BaseException) -> bool:
    return "retryable challenge response" in str(exc) or not re.search(r"\bHTTP\s+\d{3}\b", str(exc))


def is_challenge_http_error(status: int, headers: Any, raw: str) -> bool:
    if status != 403:
        return False
    mitigated = ""
    try:
        mitigated = str(headers.get("x-vercel-mitigated", "") or headers.get("X-Vercel-Mitigated", "")).strip()
    except AttributeError:
        mitigated = ""
    if mitigated and mitigated.lower() != "none":
        return True
    return bool(re.search(r"vercel", raw, re.IGNORECASE) and re.search(r"security checkpoint|challenge|bot protection", raw, re.IGNORECASE))


def validate_text(name: str, value: Any, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    clean = strip_control_chars(value).strip()
    if not 1 <= len(clean) <= max_length:
        raise ValueError(f"{name} must be 1 to {max_length} characters after control-character stripping.")
    return clean


def validate_record_id(value: Any) -> str:
    clean = validate_text("record_id", value, 128)
    if not ECHO_RECORD_ID_RE.fullmatch(clean):
        raise ValueError("record_id must be an Agent Trust Record id like atr_0123456789abcdef.")
    return clean


def validate_enum(name: str, value: Any, values: set[str]) -> str:
    if isinstance(value, str) and value in values:
        return value
    raise ValueError(f"{name} must be one of: {', '.join(sorted(values))}.")


def validate_non_negative_number(name: str, value: Any) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(float(value)) or value < 0:
        raise ValueError(f"{name} must be a non-negative number.")


def validate_iso_datetime(name: str, value: str) -> None:
    if not re.search(r"(Z|[+-]\d{2}:\d{2})$", value):
        raise ValueError(f"{name} must be an ISO 8601 datetime string with timezone offset.")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO 8601 datetime string with timezone offset.") from exc


def set_number(target: MutableMapping[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    validate_non_negative_number(key, value)
    target[key] = value


def map_text_list(value: Any, name: str, max_length: int, *, max_items: int) -> Optional[list[str]]:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a list of strings.")
    if len(value) > max_items:
        raise ValueError(f"{name} must contain at most {max_items} entries.")
    return [validate_text(name, item, max_length) for item in value]


def required(input_data: Mapping[str, Any], key: str) -> Any:
    value = input_data.get(key)
    if value is None:
        raise ValueError(f"{key} is required.")
    return value


def aliased_value(input_data: Mapping[str, Any], snake_key: str, camel_key: str) -> Any:
    snake_value = input_data.get(snake_key)
    camel_value = input_data.get(camel_key)
    if snake_value is not None and camel_value is not None and snake_value != camel_value:
        raise ValueError(f"Conflicting values supplied for {snake_key} and {camel_key}.")
    return snake_value if snake_value is not None else camel_value


def strip_control_chars(value: str) -> str:
    return CONTROL_CHARS.sub("", value)


def _clean_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    clean = value.strip()
    return clean or None


def unknown_freshness() -> Dict[str, Any]:
    return {
        "updated_at": None,
        "age_days": None,
        "status": "unknown",
        "rationale": "Preflight evidence was unavailable.",
    }


def parse_json(raw: str) -> Any:
    if not raw:
        return {}
    return json.loads(raw)


def error_message(body: Any, raw: str) -> str:
    if isinstance(body, Mapping):
        error = body.get("error")
        if isinstance(error, Mapping) and isinstance(error.get("message"), str):
            return error["message"]
        if isinstance(body.get("message"), str):
            return body["message"]
    return truncate_raw_body(raw)


def is_json_content_type(content_type: str) -> bool:
    normalized = content_type.lower()
    return "application/json" in normalized or "+json" in normalized


def truncate_raw_body(raw: str) -> str:
    clean = strip_control_chars(raw).strip()
    if not clean:
        return "empty response body"
    if len(clean) > RESPONSE_BODY_PREVIEW_CHARS:
        return clean[:RESPONSE_BODY_PREVIEW_CHARS] + "..."
    return clean
