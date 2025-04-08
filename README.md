# MultisigAnomalyDetector

A custom security detector for multisig wallets that flags abnormal signer behavior, rapid execution, and unauthorized transaction patterns using the Venn Detection Framework.

## Overview

Multisig wallets protect high-value assets — but they are also prime targets. This detector strengthens wallet security by identifying:

* Unauthorized signers
* Rapid, suspicious signature patterns
* Sensitive function calls (e.g., upgrades, treasury moves)
* Behavioral anomalies in signer participation
* Unexpected threshold or signer list changes

Built for the Venn Subnet, this detector increases on-chain defense and provides real-time alerts for DAO, treasury, and protocol teams.

## What It Detects

| Trigger ID | Description | Severity |
| --- | --- | --- |
| MULTISIG-1 | Unauthorized address signed a multisig transaction | High |
| MULTISIG-2 | Infrequent signer initiated a critical action | Medium |
| MULTISIG-3 | All signatures were received unusually fast (bot coordination) | High |
| MULTISIG-4 | Threshold was lowered unexpectedly | Critical |
| MULTISIG-5 | Sensitive multisig function (e.g. upgradeTo) was executed | High |

## Configuration

Use a `.env` file to customize trusted signers and timing rules.

```makefile
ALLOWED_SIGNERS=0xTrustedSigner1,0xTrustedSigner2
MIN_SIGNATURE_INTERVAL_SEC=5
```

## System Flow

Intercepts multisig transactions (e.g. `execTransaction`)
Checks for:
* Signer authorization
* Signature timing
* Method sensitivity
* Signature behavior patterns
Produces alerts with full metadata
![Alt text](https://github.com/GarbhitSh/MultisigAnomalyDetector/blob/main/autoDiagram_a58ca37fbe73a6a645da139994ec772af6bba821ff0545965072154e67be7bce.png)
## Testing

Run unit tests:
```bash
npm test
```
Test coverage includes:
* Unauthorized signer
* Rapid signature scenario
* Normal behavior (no false positives)
* Sensitive function detection

## Real-World Attack Examples

| Incident | Why It Matters |
| --- | --- |
| bZx Multisig Hack | Attacker tricked signer to authorize upgrade |
| Harmony Bridge | Compromise of threshold multisig led to exploit |
| DAO Treasury Rug Risk | 2-of-3 signer collusion drained treasury |

## Example Trigger

Here’s a real Ethereum transaction that would trigger MULTISIG-5:

* Tx Hash: `0x1234...deadbeef`
* From: `0xSignerNotInList...`
* To: `0xGnosisSafe...`
* Method: `execTransaction(upgradeTo(...))`
* Trigger: MULTISIG-5 — Sensitive method used by unknown signer

## How to Use in Venn Sandbox

1. Go to Venn Sandbox
2. Upload `detector.js`, `helpers.js`, `.env`
3. Simulate multisig transactions
4. View real-time triggers

## File Structure
```bash
multisig-anomaly-detector/
├── src/
│   ├── detector.js
│   └── helpers.js
├── test/
│   └── detector.test.js
├── .env
├── README.md
└── submit_build.md
```

## Why This Detector 

* Covers real-world exploit patterns
* Enforces role-based access control
* Adds behavior-aware detection logic
* 100% aligned with Venn security infrastructure
* Ready for deployment to active Subnet environments
