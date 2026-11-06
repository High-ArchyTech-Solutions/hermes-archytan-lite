"""archytan-lite — the official Python client for Archytan Lite's fail-closed contract.

THE RULE THIS MODULE EXISTS TO ENFORCE: only an HTTP 200 response whose body
has ``decision == "ALLOW"`` AND a ``receipt.signature`` that verifies against
the gate's known public key AND a receipt describing *this* request counts as
authorized. Every other outcome — a non-200 status, a timeout, a connection
refusal, a malformed body, a signature that doesn't verify, the gate process
being dead — is denied. No path here returns ``allowed=True`` without that
exact shape, and no path raises for a denial: an exception a caller forgets to
catch is an exception that skips the deny.

This is a sibling of ``clients/node/index.js`` and of the ``authorize()``
helper in ``testing/failclosed/failclosed_test.go``. The three are the same
contract in three languages and must not drift apart — if you change the
decision logic here, change it there.

On signature verification: the gate signs ``intent_hash``, a SHA-256 over the
receipt's action, resource, actor, decision and the idempotency key this client
sent, not the fields shown beside it. Checking the signature alone would let a
genuine signature be paired with rewritten fields, so this client recomputes
``intent_hash`` from those fields first, reproducing Go's ``encoding/json``
output byte for byte (see ``_go_json_string``), and only then verifies the
signature over the recomputed hash. The encoding is held to
``clients/testdata/intent_vectors.json``, generated from the Go implementation,
so it cannot drift silently.

Two runtime dependencies, both deliberate: ``cryptography`` because Python has
no Ed25519 in its standard library and hand-rolling one for a security client
would be indefensible, and ``httpx`` because it gives sync and async transports
through one API.
"""

from __future__ import annotations

import functools
import hashlib
import re
import ssl
from dataclasses import dataclass, field
from typing import Any, Mapping

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = [
    "AuthorizeResult",
    "Capability",
    "RedeemResult",
    "authorize",
    "authorize_async",
    "redeem_capability",
    "redeem_capability_async",
    "verify_receipt",
    "compute_intent_hash",
    "verify_receipt_signature",
    "receipt_mismatch",
    "RECEIPT_TAG",
    "RECEIPT_TAG_V2",
]

# The domain-separation tag the gate signs receipts under. A signature made
# under any other tag — a capability's, a license's — will not verify here,
# which is the entire point of the gate having separate tags.
RECEIPT_TAG = b"ARCHYTAN_LITE_RECEIPT_V1:"
# The tag a version 2 receipt is signed under (Archytan Lite 2.4 and later).
RECEIPT_TAG_V2 = b"ARCHYTAN_LITE_RECEIPT_V2:"

# The fields only a version 2 receipt carries. A v1 receipt that carries any
# of them has been added to: its signature covers none.
_V2_ONLY_FIELDS = (
    "receipt_version", "caller_id", "resource_tenant_id", "policy_sha256",
    "callers_sha256", "mode", "observe_override", "otel_trace_id", "created_at",
)


def _receipt_version(receipt: Mapping[str, Any]) -> int | None:
    """1 for a receipt with no version field (v1 receipts never have one), 2
    when it says so, ``None`` for anything else."""
    if not isinstance(receipt, Mapping):
        return None
    if "receipt_version" not in receipt:
        return None if any(f in receipt for f in _V2_ONLY_FIELDS) else 1
    v = receipt["receipt_version"]
    return 2 if type(v) is int and v == 2 else None

DEFAULT_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class Capability:
    """The single-use grant returned alongside an ALLOW.

    Present only when the gate has capabilities enabled. Holding one is not
    permission to act — it has to be spent via :func:`redeem_capability`
    immediately before acting, and the gate refuses a second redemption.
    """

    token: str
    cap_id: str
    expires_at: str


@dataclass(frozen=True)
class AuthorizeResult:
    """The outcome of an authorization request.

    ``allowed`` is the only field a caller should branch on.
    """

    allowed: bool
    reason: str = ""
    trace_id: str | None = None
    receipt: Mapping[str, Any] | None = None
    capability: Capability | None = None


@dataclass(frozen=True)
class RedeemResult:
    """The outcome of spending a capability.

    ``redeemed`` is true only when this call is the one that spent it.
    """

    redeemed: bool
    reason: str = ""
    cap_id: str | None = None
    receipt_id: str | None = None


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------


def verify_receipt_signature(receipt: Mapping[str, Any], gate_public_key_hex: str) -> bool:
    """Verify only a receipt's Ed25519 signature over its ``intent_hash``.

    On its own this does not prove the receipt's fields are the ones that were
    signed; use ``verify_receipt`` for that. Returns ``False`` on malformed
    input rather than raising. A caller reaching for this function is deciding
    whether to trust something; handing it an exception to catch invites a bare
    ``except`` that swallows the answer.
    """
    try:
        version = _receipt_version(receipt)
        if version is None:
            return False
        tag = RECEIPT_TAG_V2 if version == 2 else RECEIPT_TAG
        intent_hash = receipt["intent_hash"]
        signature = receipt["signature"]
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(gate_public_key_hex))
        public_key.verify(bytes.fromhex(signature), tag + bytes.fromhex(intent_hash))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


_HEX = "0123456789abcdef"

# Go's encoding/json string escapes, HTML escaping included. The two line
# separators are built with chr() so no raw separator character ever sits in
# this source file.
_GO_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "<": "\\u003c",
    ">": "\\u003e",
    "&": "\\u0026",
    chr(0x2028): "\\u2028",
    chr(0x2029): "\\u2029",
}

_INTENT_FIELDS = ("action", "resource_type", "resource_id", "actor_uid", "actor_role", "decision")

# What a v2 signature covers, in the gate's order, with each field's JSON
# type. "idempotency_key" comes from the caller, never from the receipt.
_INTENT_FIELDS_V2 = (
    ("receipt_id", str), ("operator_urn", str), ("trace_id", str), ("created_at", str),
    ("action", str), ("resource_type", str), ("resource_id", str), ("resource_tenant_id", str),
    ("actor_uid", str), ("actor_role", str), ("caller_id", str), ("decision", str),
    ("mode", str), ("observe_override", bool), ("policy_sha256", str), ("callers_sha256", str),
    ("idempotency_key", None), ("otel_trace_id", str),
)


def _go_json_string(s: str) -> str | None:
    """Encode ``s`` exactly as Go's ``encoding/json`` encodes a string.

    Every character not escaped above, non-ASCII included, is kept as raw
    UTF-8, which is why this is not ``json.dumps`` (whose default
    ``ensure_ascii=True`` would escape it). Returns ``None`` for a lone
    surrogate, which Go never emits, so the caller denies.
    """
    out = ['"']
    for ch in s:
        c = ord(ch)
        if 0xD800 <= c <= 0xDFFF:
            return None
        escaped = _GO_ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif c < 0x20:
            out.append("\\u00" + _HEX[c >> 4] + _HEX[c & 0xF])
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def compute_intent_hash(receipt: Mapping[str, Any], idempotency_key: str) -> str | None:
    """Recompute a receipt's ``intent_hash`` exactly as the gate does.

    Returns lowercase hex, or ``None`` if a field is missing, is not a string,
    or cannot be encoded the way the gate encodes it.
    """
    if not isinstance(idempotency_key, str):
        return None
    version = _receipt_version(receipt)
    if version is None:
        return None
    if version == 2:
        return _compute_intent_hash_v2(receipt, idempotency_key)
    parts = []
    for name in _INTENT_FIELDS:
        value = receipt.get(name)
        if not isinstance(value, str):
            return None
        encoded = _go_json_string(value)
        if encoded is None:
            return None
        parts.append(f'"{name}":{encoded}')
    encoded_key = _go_json_string(idempotency_key)
    if encoded_key is None:
        return None
    parts.append(f'"idempotency_key":{encoded_key}')
    canonical = "{" + ",".join(parts) + "}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_intent_hash_v2(receipt: Mapping[str, Any], idempotency_key: str) -> str | None:
    parts = ['"receipt_version":2']
    for name, kind in _INTENT_FIELDS_V2:
        if kind is None:
            encoded = _go_json_string(idempotency_key)
        elif kind is bool:
            value = receipt.get(name)
            if type(value) is not bool:
                return None
            encoded = "true" if value else "false"
        else:
            value = receipt.get(name)
            if not isinstance(value, str):
                return None
            encoded = _go_json_string(value)
        if encoded is None:
            return None
        parts.append(f'"{name}":{encoded}')
    canonical = "{" + ",".join(parts) + "}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_receipt(receipt: Mapping[str, Any], gate_public_key_hex: str, idempotency_key: str) -> str | None:
    """Full receipt check.

    The receipt's fields plus the idempotency key the caller sent must hash to
    its ``intent_hash``, and that hash must carry a valid signature from the
    gate. Returns ``None`` when genuine, otherwise the reason it is not.
    """
    recomputed = compute_intent_hash(receipt, idempotency_key)
    if recomputed is None:
        return "receipt fields are missing or not encodable"
    if recomputed != receipt.get("intent_hash"):
        return "receipt fields do not hash to its intent_hash"
    if not verify_receipt_signature(receipt, gate_public_key_hex):
        return "receipt signature did not verify against gate_public_key_hex"
    return None


def receipt_mismatch(
    receipt: Mapping[str, Any],
    request: Mapping[str, Any],
    expected_policy_sha256: str | None = None,
) -> str | None:
    """Describe the first field where ``receipt`` disagrees with the request it
    is meant to authorize, or ``None`` when every field matches.

    This is not redundant with the signature check. A valid signature proves the
    gate minted *a* receipt; it says nothing about whether this is the receipt
    for the request just made. Without this comparison, a signed ALLOW for
    "read invoice 7" replayed by a caching proxy or a stale retry would wave
    through "delete tenant 99".

    ``actor_role`` is compared only when the caller actually asserted one.
    Against a gate running credential-bound roles the correct request omits it
    — the role is a property of the credential — and the receipt then carries
    the role the gate resolved, which this client has nothing to compare
    against and no business second-guessing. Comparing an absent request role
    against a present receipt role would reject every legitimate ALLOW from a
    bound-mode gate.

    A v2 receipt also records the resource's tenant and the policy the gate
    decided under. Each is compared when there is something to compare
    against: ``resource["tenant_id"]`` in the request, or
    ``expected_policy_sha256``. A v1 receipt records neither, so pinning either
    refuses it.
    """
    actor = request.get("actor") or {}
    resource = request.get("resource") or {}

    checks: list[tuple[str, Any, Any]] = [
        ("action", receipt.get("action"), request.get("action")),
        ("resource_type", receipt.get("resource_type"), resource.get("type")),
        ("resource_id", receipt.get("resource_id"), resource.get("id")),
        ("actor_uid", receipt.get("actor_uid"), actor.get("uid")),
    ]

    requested_role = actor.get("role")
    if requested_role:
        checks.append(("actor_role", receipt.get("actor_role"), requested_role))

    is_v2 = receipt.get("receipt_version") == 2
    requested_tenant = resource.get("tenant_id")
    if requested_tenant:
        checks.append(("resource_tenant_id", receipt.get("resource_tenant_id") if is_v2 else None, requested_tenant))
    if expected_policy_sha256:
        checks.append(("policy_sha256", receipt.get("policy_sha256") if is_v2 else None, expected_policy_sha256))

    for name, got, want in checks:
        if got != want:
            return f"{name}: receipt says {got!r}, request asked for {want!r}"
    return None


# ---------------------------------------------------------------------------
# Decision logic, shared by the sync and async transports
# ---------------------------------------------------------------------------
#
# The transports below differ only in how bytes are moved. Every decision —
# what counts as an ALLOW, when a receipt is trusted, what a failure means —
# lives in these pure functions, called by both. Two copies of security
# decision logic is precisely how a sync path and an async path end up
# disagreeing about what "authorized" means, with only one of them audited.


def _decide_authorize(
    status: int,
    body: Any,
    request: Mapping[str, Any],
    gate_public_key_hex: str,
    expected_policy_sha256: str | None = None,
) -> AuthorizeResult:
    if not isinstance(body, dict):
        return AuthorizeResult(False, "gate_denied: response body was not a JSON object")

    trace_id = body.get("trace_id")

    # Every non-ALLOW path the gate has — bad token, unknown action,
    # disallowed role, malformed request, a genuine policy BLOCK, a
    # rate-limit — returns the same envelope shape. Trust the status
    # uniformly rather than branching on which failure it was.
    if status != 200:
        return AuthorizeResult(False, f"gate_denied: non-200 status {status}", trace_id)

    receipt = body.get("receipt")
    if (
        body.get("decision") != "ALLOW"
        or not isinstance(receipt, dict)
        or not receipt.get("signature")
        or not receipt.get("intent_hash")
    ):
        return AuthorizeResult(False, f"gate_denied: decision={body.get('decision')}", trace_id)

    invalid = verify_receipt(receipt, gate_public_key_hex, request.get("idempotency_key"))
    if invalid:
        return AuthorizeResult(False, f"gate_denied: {invalid}", trace_id)

    mismatch = receipt_mismatch(receipt, request, expected_policy_sha256)
    if mismatch:
        return AuthorizeResult(
            False, f"gate_denied: receipt does not match this request ({mismatch})", trace_id
        )

    raw_capability = body.get("capability")
    capability = None
    if isinstance(raw_capability, dict) and raw_capability.get("token"):
        capability = Capability(
            token=raw_capability.get("token", ""),
            cap_id=raw_capability.get("cap_id", ""),
            expires_at=raw_capability.get("expires_at", ""),
        )

    return AuthorizeResult(True, "", trace_id, receipt, capability)


def _decide_redeem(status: int, body: Any) -> RedeemResult:
    if not isinstance(body, dict):
        return RedeemResult(False, "gate_denied: response body was not a JSON object")

    if status != 200 or body.get("decision") != "ALLOW":
        # A refusal here means something different from a policy BLOCK at
        # authorize time: the decision was already made and granted, so this
        # is an expired, out-of-scope, already-spent, or forged capability.
        # Every one of those is a reason not to act.
        return RedeemResult(False, f"gate_denied: redemption refused with status {status}")

    return RedeemResult(True, "", body.get("cap_id"), body.get("receipt_id"))


def _authorize_payload(
    action: str,
    actor: Mapping[str, Any],
    resource: Mapping[str, Any],
    idempotency_key: str,
) -> dict[str, Any]:
    return {
        "action": action,
        "actor": dict(actor),
        "resource": dict(resource),
        "idempotency_key": idempotency_key,
    }


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _tls_context() -> ssl.SSLContext:
    """The TLS context every call uses, built once per process.

    httpx builds a new TLS context, loading the whole CA bundle, for every
    client it creates, and each call here creates one. On Windows that
    measured 0.3 to 1 second a call, even for a plain-HTTP gate on the same
    host. This is the context httpx would build by default, built once and
    reused; a change to SSL_CERT_FILE or SSL_CERT_DIR after the first call
    isn't picked up.
    """
    return httpx.create_ssl_context()


def authorize(
    *,
    url: str,
    token: str,
    gate_public_key_hex: str,
    action: str,
    actor: Mapping[str, Any],
    resource: Mapping[str, Any],
    idempotency_key: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    traceparent: str | None = None,
    expected_policy_sha256: str | None = None,
) -> AuthorizeResult:
    """Ask the gate whether an action may be performed.

    Never raises for a denial or a transport failure — both come back as
    ``allowed=False``.

    Omit ``actor["role"]`` against a gate running credential-bound roles: the
    role comes from your credential, and a role asserted here that disagrees
    with it is treated as an escalation attempt and refused.

    ``traceparent`` is the calling trace's W3C traceparent. The gate logs its
    trace and span ids beside the decision. A value that isn't a valid
    version-00 traceparent is not sent, so it can never cause a refusal.

    ``expected_policy_sha256``, when given, accepts an ALLOW only if its v2
    receipt says the gate decided under exactly that policy file; a v1
    receipt, which records no policy, is refused.
    """
    if not gate_public_key_hex:
        # Fail closed on misconfiguration too. Without the key nothing below
        # can be genuinely verified, so don't pretend otherwise.
        return AuthorizeResult(False, "misconfigured: gate_public_key_hex is required")

    request = _authorize_payload(action, actor, resource, idempotency_key)

    try:
        response = httpx.post(
            f"{url}/v1/authorize",
            json=request,
            headers=_headers(token, traceparent),
            timeout=timeout,
            verify=_tls_context(),
        )
    except httpx.HTTPError as exc:
        # A connection refusal, a DNS failure, and a timeout all land here.
        # The gate being unreachable is indistinguishable from the gate
        # saying no, and must be treated the same way.
        return AuthorizeResult(False, f"gate_unreachable: {exc}")

    return _decide_authorize(
        response.status_code, _json_or_none(response), request, gate_public_key_hex, expected_policy_sha256
    )


async def authorize_async(
    *,
    url: str,
    token: str,
    gate_public_key_hex: str,
    action: str,
    actor: Mapping[str, Any],
    resource: Mapping[str, Any],
    idempotency_key: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    traceparent: str | None = None,
    expected_policy_sha256: str | None = None,
) -> AuthorizeResult:
    """Async form of :func:`authorize`, with identical decision logic."""
    if not gate_public_key_hex:
        return AuthorizeResult(False, "misconfigured: gate_public_key_hex is required")

    request = _authorize_payload(action, actor, resource, idempotency_key)

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=_tls_context()) as client:
            response = await client.post(
                f"{url}/v1/authorize", json=request, headers=_headers(token, traceparent)
            )
    except httpx.HTTPError as exc:
        return AuthorizeResult(False, f"gate_unreachable: {exc}")

    return _decide_authorize(
        response.status_code, _json_or_none(response), request, gate_public_key_hex, expected_policy_sha256
    )


def redeem_capability(
    *,
    url: str,
    token: str,
    capability_token: str,
    action: str,
    resource: Mapping[str, Any],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    traceparent: str | None = None,
) -> RedeemResult:
    """Spend a capability at the gate immediately before acting on it.

    This is the call that turns the gate from an opinion into a guardrail. A
    receipt proves a decision was made; a redeemed capability is the gate's
    confirmation that this specific action, on this specific resource, has not
    already been performed and may proceed now. An actuator that acts without
    redeeming is exactly as unguarded as it was before capabilities existed —
    the gate cannot enforce what it is never asked about.
    """
    if not capability_token:
        return RedeemResult(False, "misconfigured: capability_token is required")

    payload = _redeem_payload(capability_token, action, resource)

    try:
        response = httpx.post(
            f"{url}/v1/redeem",
            json=payload,
            headers=_headers(token, traceparent),
            timeout=timeout,
            verify=_tls_context(),
        )
    except httpx.HTTPError as exc:
        return RedeemResult(False, f"gate_unreachable: {exc}")

    return _decide_redeem(response.status_code, _json_or_none(response))


async def redeem_capability_async(
    *,
    url: str,
    token: str,
    capability_token: str,
    action: str,
    resource: Mapping[str, Any],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    traceparent: str | None = None,
) -> RedeemResult:
    """Async form of :func:`redeem_capability`, with identical decision logic."""
    if not capability_token:
        return RedeemResult(False, "misconfigured: capability_token is required")

    payload = _redeem_payload(capability_token, action, resource)

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=_tls_context()) as client:
            response = await client.post(
                f"{url}/v1/redeem", json=payload, headers=_headers(token, traceparent)
            )
    except httpx.HTTPError as exc:
        return RedeemResult(False, f"gate_unreachable: {exc}")

    return _decide_redeem(response.status_code, _json_or_none(response))


def _redeem_payload(
    capability_token: str, action: str, resource: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "token": capability_token,
        "action": action,
        "resource_type": resource.get("type"),
        "resource_id": resource.get("id"),
    }


# A W3C traceparent in the only version the gate reads (00), with lowercase
# hex and no all-zero ids. Anything else is left off the request rather than
# sent: tracing must never be the reason a call fails or is refused.
_TRACEPARENT = re.compile(r"00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-[0-9a-f]{2}")


def _headers(token: str, traceparent: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if isinstance(traceparent, str) and _TRACEPARENT.fullmatch(traceparent):
        headers["traceparent"] = traceparent
    return headers


def _json_or_none(response: httpx.Response) -> Any:
    """Parse a response body, returning ``None`` when it isn't JSON.

    A body that can't be parsed is not an exception to propagate — it is a gate
    that said something this client cannot understand, which is a denial.
    """
    try:
        return response.json()
    except ValueError:
        return None
