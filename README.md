# mpp-compliance-adapter

A framework-agnostic **compliance gate for the Machine Payments Protocol (MPP)** — the reference implementation behind the companion extension draft `draft-payment-compliance-00` (payer screening before settlement).

It wraps any MPP resource handler of the form `(Request) => Response` (for example `mppx.charge({...})(request)`) and uses only hooks the core Payment scheme already provides:

- **Challenge**: appends a `compliance` parameter to the `402` `WWW-Authenticate: Payment` challenge (core §9.3 additional parameter; clients that don't know it ignore it; not part of the HMAC binding).
- **Settlement**: after the credential is verified and before settlement, screens the payer derived from `Credential.source` (`did:pkh:eip155:<chainId>:<address>`). `FAIL` → `403 application/problem+json` (core §4.2 "payment verified, but policy denies access"). `UNCERTAIN` → `403` with `retry: true` and `Retry-After` (fail-closed by default). Never settles on a failed or unknown screen.
- **Receipt**: on a settled response adds a `Payment-Compliance` header — a compact, challenge-bound screening record next to `Payment-Receipt`, so receipts can be audited.

Honest scope: this is *compliance risk screening* (sanctions / mixer / issuer-freeze / on-chain risk signals with click-through evidence). `PASS` means "this provider found no reason to block", not "safe". Unknown is `UNCERTAIN`, never `PASS`.

## Run

```bash
node mpp-demo.mjs
```

Four cases against the live screening endpoint (credentials are synthetic; nothing touches a chain):

1. no credential → `402` with the `compliance` challenge parameter
2. clean payer → `200` + `Payment-Compliance` header
3. sanctioned / mixer payer → `403 application/problem+json`, not settled
4. unscreenable payer identifier → `403` + `retry: true` (fail-closed)

## Use

```js
import { complianceGate } from "./mpp.mjs";

// Next.js / any fetch-style handler
export const GET = complianceGate(mppx.charge({ amount: "0.1" })(handler), {
  blockUncertain: true,            // fail-closed (default)
  challenge: { policyUri: "https://oceanalt.com/en/rap", level: "L1" },
  onDecision: (i) => audit(i),     // { ev, payer, challengeId, action }
});
```

## RAP conformance test suite

`rap-conformance.mjs` is the runnable RAP v1.0 conformance suite — 15 vectors you can run against **any** implementation, including ours.

```bash
node rap-conformance.mjs                           # test OceanAlt (default)
node rap-conformance.mjs https://your-gateway.com  # test your own implementation
node rap-conformance.mjs https://... --json        # machine-readable output
```

Node 18+, no dependencies, nothing to install. Exit code is non-zero when a `critical` vector fails, so it works as a CI gate.

"Conformant" has exactly one definition: every `critical` vector passes. `important` failures are listed in full but do not void conformance.

This is the same assertion implementation and the same vectors OceanAlt runs against itself daily; the published scoreboard, including anything we fail, is at https://oceanalt.com/en/rap/conformance. A suite that always gives itself full marks is worth less than no suite at all — as a sanity check, run it against a site that implements nothing (`node rap-conformance.mjs https://example.com`) and it should fail most vectors.

Files: `mpp.mjs` (gate + problem details + challenge param + receipt header), `core.mjs` (protocol-agnostic screening core, calls `https://oceanalt.com/api/risk`), `mpp-demo.mjs`.

Spec draft: `specs/extensions/draft-payment-compliance-00.md` in the tempoxyz/mpp-specs PR. Framework: https://oceanalt.com/en/rap

MIT © OceanAlt
