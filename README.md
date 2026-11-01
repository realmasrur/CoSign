<p align="center">
  <img src="assets/banner.png" alt="CoSign: the independent co-signing guardrail for crypto exchanges" width="100%">
</p>

# CoSign

**The independent co-signing guardrail for crypto exchanges.**

CoSign sits between an exchange and the blockchain. A guarded withdrawal needs CoSign's
signature as well as the exchange's, and CoSign signs only what it has decoded, priced and
checked against policy by itself. If the exchange's interface, servers or operators are
compromised, the attacker still has to get a transaction past a second, independent control
that trusts nothing the exchange says, and that caps how much can leave even if a signing
path is fully compromised.

CoSign is **source-available** under a commercial subscription. See [Licensing](#licensing-and-commercial-terms).

## The exploits it is built to stop

**Bybit, February 2025 (about $1.5 billion).** Signers approved a transaction that the compromised
signing interface showed as routine. What they actually signed switched the Safe call type to a
`delegatecall` into attacker-controlled code, which replaced the wallet's logic. A multisig,
hardware wallets and cold storage were all in place. Nobody independent checked what the
transaction would really do.

**Binance, October 2026 (an estimated $6.3 billion, preliminary findings).** Binance's initial
investigation points to a compromised engineer's laptop that reached an internal service able to
submit withdrawals. No wallet key leak has been reported; the transactions were signed correctly by
Binance's own system. Analysts describe the attacker using EIP-7702 delegations to turn hot wallets
into sweepers and draining them across many chains in a few hours.

The common thread is that the signing path itself was made to approve something it should not
have. CoSign adds an independent check outside that path:

- It **recomputes exactly what will be signed** from the raw fields, and signs only those bytes.
- It **decodes the transaction itself**: Safe calldata and MultiSend batches, and raw hot-wallet transactions (legacy, 2930, 1559, 7702).
- It **blocks structural attacks**: `delegatecall` to unknown code, approvals, proxy upgrades, owner/guard/module changes, and EIP-7702 delegations.
- It **caps the blast radius**: per-transaction caps, rolling velocity limits per chain, and one **global cross-chain limit** that all chains share.
- It **fails closed** on anything it cannot fully explain or price.
- It **cannot be talked out of its limits**: loosening policy takes a quorum, a timelock, and survives a single-approver veto.

CoSign limits and blocks; it does not promise that no attack can ever succeed. What a compromised
signing path can extract is bounded by the limits you set.

## How it works

```
Safe multisig tx ─┐
raw hot-wallet tx ┼──▶ CoSigner (runs inside the enclave)
7702 authorization┘    1. recompute the digest from the parsed bytes and compare        evm
                       2. decode calldata, batches, delegations; flag risky operations  evm
                       3. price outflows from M-of-N signed feeds                       price
                       4. apply limits, allow-list, velocity, delays, global ceiling    lib
                       5. write the decision to a hash-chained log (write-ahead)        audit
                       6. sign ONLY the recomputed digest                               signer
```

If any step fails, nothing is signed.

## What is in the release

| File | Purpose |
|---|---|
| `src/lib.rs` | Policy engine: per-transaction cap, rolling velocity, allow-list, time delay, pause, plus the shared cross-chain `GlobalLimit`. Pure and deterministic. |
| `src/evm.rs` | Safe 1.3+ digest verification, MultiSend unpacking, strict canonical RLP, raw transaction decoding, EIP-7702 authorization and delegation checks. |
| `src/price.rs` | Signed multi-feed price book: highest valid price wins, rounds up, expiry, rollback and clock protection. |
| `src/signer.rs` | `CoSigner`: the single path to a signature. Idempotent retries. `Key` trait for KMS, HSM or MPC backends. |
| `src/audit.rs` | Hash-chained audit log. No signature is released without a durable log entry. |
| `src/control.rs` | Pause by any single trigger; unpause only by quorum, bound to an epoch so approvals cannot be replayed. |
| `src/change.rs` | Policy changes: tighten instantly with one approver; loosen with quorum, timelock and veto. |
| `src/keccak.rs` | Dependency-free Keccak-256. |

## Security properties

- Hashes and checks the **same bytes** it will sign, so the thing analyzed is the thing authorized.
- Strict canonical RLP: non-canonical, truncated or trailing encodings are rejected.
- Unknown selectors, unpriceable assets, wrong chain ids, contract creation, blob transactions, overflowing amounts and gas-refund payouts all block.
- EIP-7702 delegations are blocked unless to an explicitly allowed contract on the same chain; all-chain delegations are always blocked.
- Velocity is reserved at approval time, per chain and globally, with an atomic check-and-reserve on the shared limit.
- The global limit has no runtime change path; changing it means redeploying the attested enclave.
- Prices need M distinct signed feeds, are rounded up, expire, and cannot be rolled back.
- Pause is instant and works even if logging is down. Unpause needs a quorum.
- A compromised administrator cannot raise limits alone.

## Deployment requirements

CoSign protects a wallet only when deployed as designed:

1. **Required signer.** CoSign's key must be a required signer on each guarded wallet: a multisig owner, or a required MPC key share for hot wallets. Wallets that can move funds without it are not covered.
2. **Independence.** Run it on separate infrastructure from the exchange: different cloud account, organization, keys and operators.
3. **Key custody.** Approver keys, price-feed keys and the audit-log anchor must each be independent of the exchange and held by different people on hardware-backed keys.
4. **Enclave execution.** Hold the signing key only inside the enclave or HSM, never in normal host memory.
5. **One instance per chain**, each with its own `EvmConfig` and `PriceBook`, all attached to one shared `GlobalLimit`.
6. **Sensible limits.** Set per-chain and global limits relative to your real withdrawal flow. The limits are what bound the loss.

## Scope of this release

This release provides the policy, decoding, pricing, signing, audit and governance core for **EVM chains**, covering **Safe multisig withdrawals** and **raw hot-wallet transactions**, including EIP-7702 handling. Plan integration around what is not included:

- Network service, enclave host and attested key provisioning (AWS Nitro, SGX or HSM).
- MPC protocol adapters. `Key` is the integration point; the policy gate in front of it is what this release delivers.
- Non-EVM chains. The `GlobalLimit` is chain-agnostic and is ready to be shared by future chain adapters.
- State-based EVM simulation. Decoding is static; calldata CoSign cannot explain is blocked rather than simulated.
- Anomaly detection. Limits cap what can leave; they do not detect abnormal-but-within-limit activity.
- Persistence of velocity and pending-delay state across restarts.
- Dashboards and alert delivery.

The release has not been independently audited. Have your deployment reviewed before it guards live funds. See [SECURITY.md](SECURITY.md).

## Licensing and commercial terms

CoSign is licensed under the **CoSign Commercial Source-Available License 1.0** ([LICENSE](LICENSE)). It is source-available, not open source.

| Included with an active annual subscription | Not permitted |
|---|---|
| Deploy in your own environments to guard your platforms' withdrawals | Modifying the code |
| Staging, test and disaster-recovery copies | Redistribution, mirrors or publishing |
| Configuring policy, keys, feeds and allow-lists | Creating or hosting forks |
| Reading and auditing the source, including by your security auditors | Offering CoSign as a service to others |
| Updates and security patches during the term | Building a competing product from it |
| A 90-day transition period at the end of a term so funds are never trapped | Use after the term, outside the transition period |

Key terms:

- **Annual subscription**, renewing yearly, priced per Order Form. Fees and covered platforms are set there.
- **Patches, not forks.** You can request changes; Licensor-issued patches are applied by you. Critical security updates are to be deployed within 14 days.
- **Evaluation.** Anyone may review the source and test in a non-production environment for 30 days. Evaluation may not guard live funds.
- **Coordinated disclosure.** Vulnerabilities are reported privately; public disclosure waits for a fix or 90 days.
- **Repository access.** Visibility of this repository, or any platform feature that allows copying, does not grant a license. Copies and forks made without written authorization are unlicensed.

The license text governs. For subscriptions, pricing and the Order Form, use the licensing contact in [LICENSE](LICENSE) Section 14(g).

## Build and test

```
cargo test                    # standard library only
cargo test --features k256    # also builds LocalKey and Secp256k1Verifier
```

Building from source is part of your licensed review and deployment rights. Do not publish builds or artifacts.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

---

Copyright © 2026 Masrur Ahmmed. All rights reserved.
