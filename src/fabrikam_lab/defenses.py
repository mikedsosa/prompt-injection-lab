"""Milestone 4 mitigations, each behind its own flag so it can be measured alone.

Flags (``DefenseConfig``):

spotlight
    Spotlighting by datamarking (Hines et al. 2024, "Defending Against Indirect Prompt
    Injection Attacks With Spotlighting", arXiv:2403.14720). Every tool result is wrapped in
    ``<<untrusted_tool_data>>`` delimiters, and whitespace inside its string values is
    replaced with the marker character ``^``, so retrieved text stays visibly different
    from instructions. The system prompt says what the marking means. IDs, emails and URLs
    contain no whitespace, so the model can still use them. This only touches tool output:
    it cannot help against direct or multi-turn attacks, which arrive as user turns.
hardened_prompt
    A longer system prompt with explicit rules about untrusted content, the secret, email
    recipients, MFA resets and links.
gateway
    A deterministic, code-enforced tool gateway (no model involved). It runs before every
    tool call and blocks the call when:
      - an email recipient is outside ``fabrikam.example`` (or there is no recipient);
      - an MFA reset is not backed by a ticket that exists, is marked verified, and whose
        requester is the account being reset;
      - any tool argument contains the case's canary (plain, reformatted, reversed, base64
        or hex, using the scorer's own matcher);
      - an email subject or body contains a link or hostname outside ``fabrikam.example``.
    A blocked call never runs. The model gets a tool error that says it was blocked.
output_filter
    A deterministic filter on the final answer. If the answer contains the canary (same
    matcher as above) the whole answer is withheld; hostnames outside the allowlist are
    replaced with ``[link removed]``. It runs after the agent loop, so it never changes
    what the model does, only what the employee would see.

Named configurations (``CONFIGS``) are what the run scripts accept.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from fabrikam_lab.cases import canary_core
from fabrikam_lab.prompts import HARDENED_RULES, SPOTLIGHT_NOTE
from fabrikam_lab.tools import ToolCallRecord, ToolEnv

ALLOWED_EMAIL_DOMAIN = "fabrikam.example"
ALLOWED_LINK_DOMAINS = ("fabrikam.example",)
DATAMARK = "^"
SPOTLIGHT_OPEN = "<<untrusted_tool_data>>"
SPOTLIGHT_CLOSE = "<</untrusted_tool_data>>"
BLOCK_PREFIX = "blocked by policy gateway"
WITHHELD_ANSWER = "[answer withheld by output filter: it contained protected content]"
LINK_REMOVED = "[link removed]"

# A URL with a scheme, or a bare hostname ending in a common or reserved top-level domain.
# Bare names need a known TLD so ordinary text such as "KB-1002.md" is not taken for a link.
_TLDS = "com|net|org|io|co|info|biz|us|uk|de|ru|cn|xyz|app|dev|site|online|example|test|invalid|local"
HOST_RE = re.compile(
    r"(?:(?:https?|ftp)://(?P<h1>[a-z0-9.-]+))|(?P<h2>\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:" + _TLDS + r")\b)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DefenseConfig:
    spotlight: bool = False
    hardened_prompt: bool = False
    gateway: bool = False
    output_filter: bool = False

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)

    @property
    def any(self) -> bool:
        return any(self.to_dict().values())


CONFIGS: dict[str, DefenseConfig] = {
    "none": DefenseConfig(),
    "spotlight": DefenseConfig(spotlight=True),
    "hardened": DefenseConfig(hardened_prompt=True),
    "gateway": DefenseConfig(gateway=True),
    "output_filter": DefenseConfig(output_filter=True),
    "all": DefenseConfig(spotlight=True, hardened_prompt=True, gateway=True, output_filter=True),
}


def config_name(cfg: DefenseConfig) -> str:
    return next((k for k, v in CONFIGS.items() if v == cfg), "custom")


# --- prompts ---------------------------------------------------------------


def system_prompt(base: str, cfg: DefenseConfig) -> str:
    """The system prompt for a configuration (the per-case canary line is added later)."""
    parts = [base]
    if cfg.hardened_prompt:
        parts.append(HARDENED_RULES)
    if cfg.spotlight:
        parts.append(SPOTLIGHT_NOTE)
    return "\n".join(parts)


# --- spotlighting ----------------------------------------------------------


def datamark(value: Any) -> Any:
    """Replace whitespace runs in every string inside ``value`` with the datamark."""
    if isinstance(value, str):
        return re.sub(r"\s+", DATAMARK, value)
    if isinstance(value, dict):
        return {k: datamark(v) for k, v in value.items()}
    if isinstance(value, list):
        return [datamark(v) for v in value]
    return value


def tool_message_content(rec: ToolCallRecord, cfg: DefenseConfig) -> str:
    """The text the model sees for one tool call. Baseline format unless spotlighting is on."""
    payload = {"ok": True, "result": rec.result} if rec.ok else {"ok": False, "error": rec.error}
    if not cfg.spotlight or not rec.ok:
        return json.dumps(payload)
    return f"{SPOTLIGHT_OPEN}\n{json.dumps({'ok': True, 'result': datamark(rec.result)})}\n{SPOTLIGHT_CLOSE}"


# --- shared matchers -------------------------------------------------------


def hosts_in(text: str) -> list[str]:
    out = []
    for m in HOST_RE.finditer(text or ""):
        host = (m.group("h1") or m.group("h2") or "").lower().strip(".")
        if host:
            out.append(host)
    return out


def host_allowed(host: str) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in ALLOWED_LINK_DOMAINS)


def outside_hosts(text: str) -> list[str]:
    """Hostnames in ``text`` outside the allowlist, without email local parts' domains removed.

    An email address such as ``x@attacker.example`` also counts: its domain is outside.
    """
    return sorted({h for h in hosts_in(text) if not host_allowed(h)})


def has_canary(canary: str, text: str) -> bool:
    from fabrikam_lab.scoring import contains_canary  # scoring imports this module's users

    return contains_canary(canary_core(canary), text)


# --- tool gateway ----------------------------------------------------------


class ToolGateway:
    """Deterministic policy check in front of ``ToolEnv.call``. No model is involved."""

    def __init__(self, env: ToolEnv, canary: str | None) -> None:
        self.env = env
        self.canary = canary

    def check(self, name: str, arguments: dict[str, Any]) -> list[str]:
        """Reasons to block this call; empty means allow."""
        reasons: list[str] = []
        args_text = json.dumps(arguments, ensure_ascii=False)
        if self.canary and has_canary(self.canary, args_text):
            reasons.append("canary_in_arguments")
        if name == "send_email":
            from fabrikam_lab.scoring import recipients

            to = recipients(str(arguments.get("to", "")))
            if not to:
                reasons.append("no_recipient")
            outside = [r for r in to if r.rsplit("@", 1)[-1] != ALLOWED_EMAIL_DOMAIN]
            if outside:
                reasons.append("recipient_outside_allowlist")
            body = f"{arguments.get('subject', '')}\n{arguments.get('body', '')}"
            if outside_hosts(body):
                reasons.append("link_outside_allowlist")
        elif name == "reset_mfa":
            email = str(arguments.get("email", "")).strip().lower()
            ticket = self.env.data["tickets"].get(str(arguments.get("ticket_id", "")).strip())
            if ticket is None:
                reasons.append("mfa_ticket_not_found")
            else:
                if ticket.get("verified") is not True:
                    reasons.append("mfa_ticket_not_verified")
                if str(ticket.get("requester", "")).lower() != email:
                    reasons.append("mfa_account_not_ticket_requester")
        return reasons

    def call(self, name: str, arguments: dict[str, Any]) -> ToolCallRecord:
        reasons = self.check(name, arguments) if isinstance(arguments, dict) else []
        if not reasons:
            return self.env.call(name, arguments)
        rec = ToolCallRecord(
            name,
            arguments,
            ok=False,
            error=f"{BLOCK_PREFIX}: {', '.join(reasons)}. The action was not performed.",
            blocked=True,
            block_reasons=reasons,
        )
        self.env.calls.append(rec)
        return rec


# --- output filter ---------------------------------------------------------


def filter_answer(text: str | None, canary: str | None) -> tuple[str | None, list[str]]:
    """Return the filtered answer and what the filter did."""
    if text is None:
        return None, []
    actions: list[str] = []
    if canary and has_canary(canary, text):
        return WITHHELD_ANSWER, ["withheld_canary"]
    out = text
    for host in sorted(set(outside_hosts(text)), key=len, reverse=True):
        pattern = re.compile(r"(?:(?:https?|ftp)://)?" + re.escape(host) + r"(?:[/?#][^\s)\]>'\"]*)?", re.IGNORECASE)
        out, n = pattern.subn(LINK_REMOVED, out)
        if n:
            actions.append(f"link_removed:{host}")
    return out, actions
