# Security

## Reporting a vulnerability

Report suspected vulnerabilities privately to the licensing and security contact in
[LICENSE](LICENSE) Section 14(g), or through this repository's private vulnerability
reporting. Do not open public issues for security problems. Under LICENSE Section 9,
public disclosure waits for a fix or ninety days from the report, whichever comes first.

## Assurance status

This release has not been independently audited. Treat it as a security control that
requires your own review: have your deployment, key custody and enclave integration
reviewed independently before it guards live funds.

## Threat model

| Party | Trust |
|---|---|
| Exchange systems and operators | Untrusted. Assumed fully compromised. |
| Host running the enclave | Untrusted. Can drop, delay, reorder and replay messages, and can misreport time. |
| Enclave (CoSigner and its key) | Trusted once attested. |
| Price-feed keys | Trusted up to M-1 compromised of the configured set. |
| Approver keys | Trusted up to M-1 compromised for loosening and unpause. One key can tighten, pause or veto. |

## Design notes and limits

1. State (velocity, pending delays, signed-request cache) is held in memory and resets on restart. Restart procedures should account for this.
2. Time is host-supplied. The clock only moves forward and signed prices expire, but a trusted time source in the enclave is recommended.
3. Decoding is static. Calldata CoSign cannot explain is blocked, not simulated.
4. One approver can tighten limits sharply. This is deliberate (the fail-safe direction) and can be used to cause a temporary denial of service. Monitor for unexpected tightening.
5. A compromised feed that sends conflicting decimals for an asset can stall that asset's price refresh. This fails closed.
6. The audit-log chain detects edits, deletions and reordering. Detecting truncation of the newest entries requires anchoring the head hash outside CoSign.
7. Protection applies only to wallets where CoSign is a required signer.
8. Limits bound the loss; they do not detect abnormal activity that stays within them. Anomaly detection is not part of this release.
9. The global cross-chain limit has no runtime change path by design. Changing it requires redeploying the attested enclave, so size it with operational headroom.
10. Raw transactions are analyzed from the exact bytes supplied for signing. The caller must supply the bytes that the key or MPC backend will actually sign.
11. Prices, `EvmConfig` and policy are per chain; a misconfigured chain id fails closed because transactions and signed prices bind the chain id.
