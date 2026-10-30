<p align="center">
  <img src="assets/banner.png" alt="CoSign: the independent co-signing guardrail for crypto exchanges" width="100%">
</p>

# CoSign

**The independent co-signing guardrail for crypto exchanges.**

CoSign sits between an exchange and the blockchain. A guarded withdrawal needs CoSign's
signature as well as the exchange's, and CoSign signs only what it has decoded, priced and
checked against policy by itself. If the exchange's interface, servers or operators are
compromised, the attacker still has to get a transaction past a second, independent control
that does not trust anything the exchange says.

CoSign is **source-available** under a commercial subscription. See [Licensing](#licensing-and-commercial-terms).

## The exploit it is built to stop

In February 2025 attackers took roughly $1.5 billion from Bybit's cold wallet. The signers
approved a transaction that the compromised signing interface showed as routine. What they
actually signed changed the Safe call type from a plain call to a `delegatecall` into an
attacker-deployed contract, which replaced the wallet's logic and let the attacker sweep it.
Hardware wallets, a multisig and a cold-storage policy were all in place. Nobody independent
checked what the transaction would really do.

CoSign is that independent check:

- It **recomputes the digest** the signers will sign from the raw transaction fields, and refuses on any mismatch with what the caller claims.
- It **decodes the calldata itself**, including MultiSend batches, and blocks `delegatecall` to anything but a configured MultiSend contract.
- It **blocks control-plane changes**: approvals, proxy upgrades, and owner, threshold, guard, module and fallback-handler changes.
- It **fails closed** on anything it cannot fully explain or price.
- It **cannot be talked out of its limits**: loosening policy takes a quorum, a timelock, and survives a single-approver veto.

## How it works

```
exchange ──raw Safe transaction──▶ CoSigner (runs inside the enclave)
                                   1. recompute the EIP-712 digest and compare        evm
                                   2. decode calldata and MultiSend, flag risky ops   evm
                                   3. price outflows from M-of-N signed feeds         price
                                   4. apply limits, allow-list, velocity, delays      lib
                                   5. write the decision to a hash-chained log        audit
                                   6. sign ONLY the recomputed digest                 signer
```

If any step fails, nothing is signed.

## What is in the release

| File | Purpose |
|---|---|
| `src/lib.rs` | Policy engine: per-transaction cap, rolling velocity, allow-list, time delay, pause. Pure and deterministic. |
| `src/evm.rs` | Safe 1.3+ digest verification, MultiSend unpacking, calldata classification. |
| `src/price.rs` | Signed multi-feed price book: highest valid price wins, rounds up, expiry, rollback and clock protection. |
| `src/signer.rs` | `CoSigner`: the single path to a signature. Idempotent retries. `Key` trait for KMS or HSM keys. |
| `src/audit.rs` | Hash-chained audit log. No signature is released without a durable log entry. |
| `src/control.rs` | Pause by any single trigger; unpause only by quorum, bound to an epoch so approvals cannot be replayed. |
| `src/change.rs` | Policy changes: tighten instantly with one approver; loosen with quorum, timelock and veto. |
| `src/keccak.rs` | Dependency-free Keccak-256. |

## Security properties

- Signs only a digest it recomputed from raw fields, never one supplied by the caller.
- Unknown selectors, unpriceable assets, malformed batches, overflowing amounts and gas-refund payouts all block.
- Velocity is reserved at approval time, so parallel requests cannot slip past limits.
- Prices need M distinct signed feeds, are rounded up, expire, and cannot be rolled back.
- Pause is instant and works even if logging is down. Unpause needs a quorum.
- A compromised administrator cannot raise limits alone.

## Deployment requirements

CoSign protects a wallet only when deployed as designed:

1. **Required signer.** CoSign's key must be a required signer on each guarded wallet (multisig owner or MPC share). Wallets that can move funds without it are not covered.
2. **Independence.** Run it on separate infrastructure from the exchange: different cloud account, organization, keys and operators.
3. **Key custody.** Approver keys, price-feed keys and the audit-log anchor must each be independent of the exchange and held by different people on hardware-backed keys.
4. **Enclave execution.** Hold the signing key only inside the enclave or HSM, never in normal host memory. The optional `LocalKey` backend is for use inside an attested enclave or in tests.

## Scope of this release

This release provides the policy, decoding, pricing, signing, audit and governance core for **Safe (EVM) multisig withdrawals**. The following are outside it, so plan integration accordingly:

- Network service, enclave host and attested key provisioning (AWS Nitro, SGX or HSM). `Key` is the integration point.
- Plain EOA or MPC raw-transaction (RLP) decoding, and non-EVM chains.
- State-based EVM simulation. Decoding is static; calldata CoSign cannot explain is blocked rather than simulated.
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
