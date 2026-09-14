# AllowanceSentryAI

AllowanceSentryAI converts a documented, block-pinned EVM allowance snapshot into deterministic exposure evidence and reviewable **unsigned** revocation calldata. It runs offline, requires no wallet connection, and has no runtime dependencies.

## Concrete distinction

Connected revocation interfaces are useful for discovery and wallet-assisted action. AllowanceSentryAI serves a different workflow: reproducible evidence for audits, support tickets, incident notes, and tests. The same JSON snapshot always produces the same sorted report, exact calldata, limitations, and attention counts.

It does not fetch a wallet's complete allowance history. It analyzes observations you supply and preserves the source and block reference so the result can be challenged or regenerated.

## Safety boundary

- Never requests a private key, seed phrase, signature, wallet connection, or token approval.
- Never submits, signs, broadcasts, or simulates a transaction.
- Never calls a spender malicious, safe, trusted, or compromised.
- Never infers token prices, value at risk, identity, reputation, or intent.
- Emits calldata only for independent verification and simulation in tools you choose.

## Supported observations

- ERC-20 `allowance` values, including exact detection of the `uint256` maximum.
- ERC-721 collection-wide operator approval.
- ERC-1155 collection-wide operator approval.

The analyzer labels active exposure shapes as `unlimited`, `above-observed-balance`, `finite-active`, or `collection-wide-active`. Attention levels are deterministic sorting aids—not security verdicts.

## Run

Python 3.11 or newer is required.

```bash
./install.sh
./run.sh
```

The normal entry point opens a PySide6 control panel with live status, output,
and actions for the bundled offline demo, test suite, repair, and stop. Run the
same bundled demo directly with `./demo.sh`, or use `./cli.sh` for CLI-only
operation:

```bash
./cli.sh examples/snapshot.json
```

Write only the unsigned call bundle while still printing the full report:

```bash
python -m allowancesentry examples/snapshot.json --unsigned-out revocations.json
```

Add constrained commentary from a local OpenAI-compatible server:

```bash
python -m allowancesentry examples/snapshot.json \
  --ai-endpoint http://127.0.0.1:8080 \
  --ai-model your-local-model
```

The AI endpoint must be HTTP(S) on `localhost`, `127.0.0.1`, or `::1`. AI commentary cannot change the evidence or unsigned calls.

## Snapshot format

Every snapshot requires `chain_id`, `block_number`, `owner`, a human-readable `source`, and an `observations` array. A `block_hash` is recommended. Numeric token quantities are raw nonnegative integers, not decimal-adjusted display values. Supply them as JSON integers or canonical decimal strings (`0` or a nonzero digit followed by digits). Fractional numbers, booleans, signs, whitespace, exponents, and leading-zero strings are rejected rather than coerced.

See [`examples/snapshot.json`](examples/snapshot.json). Addresses and optional block hashes are strictly length-checked. Duplicate standard/token/actor observations are rejected instead of silently overwritten.

## Standards and limitations

The generated calls use the interfaces defined by [ERC-20](https://eips.ethereum.org/EIPS/eip-20), [ERC-721](https://eips.ethereum.org/EIPS/eip-721), and [ERC-1155](https://eips.ethereum.org/EIPS/eip-1155). Token contracts can deviate from those interfaces or revert. Independently inspect and simulate every call before considering a signature.

This release does not cover Permit2, ERC-2612 signatures, temporary or expiring approvals, proxy resolution, token-level ERC-721 approvals, historical event discovery, or contract verification.

## Test

```bash
./test.sh
```

## Support development

Donations fund additional production. A donor may open the funded-direction issue template with the asset, network, public transaction hash, and requested direction. Read [SUPPORT.md](SUPPORT.md) for attribution and safety rules.

## License

Apache-2.0. See [LICENSE](LICENSE).


`./run.sh` automatically runs the repeat-safe `./install.sh` when setup is
missing or incomplete. `./install.sh` installs or repairs every dependency and
verifies the application before marking the GUI ready.
