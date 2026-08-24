from __future__ import annotations

import re
from collections import Counter
from typing import Any

UINT256_MAX = 2**256 - 1
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_STANDARDS = {"erc20", "erc721-operator", "erc1155-operator"}


class AnalysisError(ValueError):
    """Raised when a snapshot cannot be treated as deterministic evidence."""


def _address(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ADDRESS.fullmatch(value) is None:
        raise AnalysisError(f"{field} must be a 20-byte 0x-prefixed address")
    return value.lower()


def _integer(value: Any, field: str, *, positive: bool = False) -> int:
    if isinstance(value, bool):
        raise AnalysisError(f"{field} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise AnalysisError(f"{field} must be an integer") from exc
    if result < (1 if positive else 0):
        raise AnalysisError(f"{field} is out of range")
    return result


def _word_address(address: str) -> str:
    return "0" * 24 + address[2:]


def _word_uint(value: int) -> str:
    return f"{value:064x}"


def _revocation(token: str, actor: str, standard: str) -> dict[str, Any]:
    if standard == "erc20":
        method = "approve(address,uint256)"
        data = "0x095ea7b3" + _word_address(actor) + _word_uint(0)
    else:
        method = "setApprovalForAll(address,bool)"
        data = "0xa22cb465" + _word_address(actor) + _word_uint(0)
    return {
        "to": token,
        "value": "0x0",
        "data": data,
        "method": method,
        "status": "unsigned-unsubmitted",
    }


def _analyze_erc20(item: dict[str, Any], token: str, actor: str) -> dict[str, Any]:
    amount = _integer(item.get("allowance"), "observation.allowance")
    if amount > UINT256_MAX:
        raise AnalysisError("observation.allowance exceeds uint256")
    balance_raw = item.get("balance")
    balance = None if balance_raw is None else _integer(balance_raw, "observation.balance")
    if balance is not None and balance > UINT256_MAX:
        raise AnalysisError("observation.balance exceeds uint256")

    facts: list[str] = []
    if amount == 0:
        state, attention = "inactive", "none"
    elif amount == UINT256_MAX:
        state, attention = "unlimited", "high"
        facts.append("allowance equals uint256 maximum")
    elif balance is not None and amount > balance:
        state, attention = "above-observed-balance", "medium"
        facts.append("allowance exceeds the supplied balance at the snapshot block")
    else:
        state, attention = "finite-active", "review"
        facts.append("positive finite allowance")

    result: dict[str, Any] = {
        "standard": "erc20",
        "token": token,
        "spender": actor,
        "allowance": str(amount),
        "balance": None if balance is None else str(balance),
        "state": state,
        "attention": attention,
        "facts": facts,
        "revocation": None,
    }
    if amount:
        result["revocation"] = _revocation(token, actor, "erc20")
    return result


def _analyze_operator(item: dict[str, Any], token: str, actor: str, standard: str) -> dict[str, Any]:
    approved = item.get("approved")
    if not isinstance(approved, bool):
        raise AnalysisError("operator observation.approved must be true or false")
    return {
        "standard": standard,
        "token": token,
        "operator": actor,
        "approved": approved,
        "state": "collection-wide-active" if approved else "inactive",
        "attention": "high" if approved else "none",
        "facts": ["operator approval applies across the token contract"] if approved else [],
        "revocation": _revocation(token, actor, standard) if approved else None,
    }


def analyze_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Validate and analyze a block-pinned allowance observation snapshot."""
    if not isinstance(snapshot, dict):
        raise AnalysisError("snapshot must be an object")
    chain_id = _integer(snapshot.get("chain_id"), "chain_id", positive=True)
    block_number = _integer(snapshot.get("block_number"), "block_number")
    owner = _address(snapshot.get("owner"), "owner")
    block_hash = snapshot.get("block_hash")
    if block_hash is not None and (not isinstance(block_hash, str) or _HASH.fullmatch(block_hash) is None):
        raise AnalysisError("block_hash must be a 32-byte 0x-prefixed value")
    source = snapshot.get("source")
    if not isinstance(source, str) or not source.strip():
        raise AnalysisError("source must identify how the observations were obtained")
    observations = snapshot.get("observations")
    if not isinstance(observations, list):
        raise AnalysisError("observations must be an array")

    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw in enumerate(observations):
        if not isinstance(raw, dict):
            raise AnalysisError(f"observation {index} must be an object")
        standard = raw.get("standard")
        if standard not in _STANDARDS:
            raise AnalysisError(f"observation {index} has unsupported standard")
        token = _address(raw.get("token"), f"observation {index}.token")
        actor_field = "spender" if standard == "erc20" else "operator"
        actor = _address(raw.get(actor_field), f"observation {index}.{actor_field}")
        identity = (standard, token, actor)
        if identity in seen:
            raise AnalysisError(f"observation {index} duplicates an earlier token/actor pair")
        seen.add(identity)
        entry = _analyze_erc20(raw, token, actor) if standard == "erc20" else _analyze_operator(raw, token, actor, standard)
        entry["observation_index"] = index
        entries.append(entry)

    entries.sort(key=lambda row: (row["token"], row.get("spender", row.get("operator", "")), row["standard"]))
    counts = Counter(str(entry["attention"]) for entry in entries)
    active = sum(entry["state"] != "inactive" for entry in entries)
    revocations = [entry["revocation"] | {"standard": entry["standard"]} for entry in entries if entry["revocation"]]
    return {
        "snapshot": {
            "chain_id": chain_id,
            "block_number": block_number,
            "block_hash": block_hash.lower() if block_hash else None,
            "owner": owner,
            "source": source.strip(),
        },
        "summary": {
            "observations": len(entries),
            "active": active,
            "attention": {level: counts.get(level, 0) for level in ("high", "medium", "review", "none")},
            "unsigned_revocations": len(revocations),
        },
        "entries": entries,
        "unsigned_revocations": revocations,
        "limitations": [
            "input observations are trusted only as supplied and are not independently fetched",
            "attention levels describe exposure shape, not spender identity, intent, reputation, or safety",
            "unsigned calldata must be independently verified and simulated before any wallet signs it",
            "token implementations may deviate from the referenced ERC interfaces",
        ],
    }
