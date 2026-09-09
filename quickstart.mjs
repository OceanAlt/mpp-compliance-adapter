#!/usr/bin/env node
/**
 * Ask before you pay — the smallest useful integration.
 * ===========================================================================
 * Node 18+. No dependencies. No API key. No signup. Run it:
 *
 *   node quickstart.mjs
 *   node quickstart.mjs 0xSomePayeeAddress
 *
 * What this shows: the one call an agent should make *before* it moves money,
 * and how to branch on the answer without parsing prose.
 *
 * Why branch on `signal_keys` and not on the human sentences: the prose is
 * localised (add `&lang=zh` and it comes back in Chinese). The keys are not.
 * Code that greps English strings breaks the day someone flips the language.
 *
 * "clear" means: we found nothing in the data we hold. It does NOT mean safe.
 * Absence of evidence is not evidence of safety — keep enforcing your own
 * mandate (per-payment cap, daily cap, payee allowlist) regardless.
 *
 * Docs: https://oceanalt.com/en/api-docs   Standard: https://oceanalt.com/en/rap
 * License: MIT
 * ===========================================================================
 */

const BASE = "https://oceanalt.com";

/** One call. Returns a structured verdict plus click-through evidence. */
async function screen(address, { network = "ethereum", lang = "en" } = {}) {
  const url = new URL("/api/risk", BASE);
  url.searchParams.set("addr", address);
  url.searchParams.set("network", network);
  url.searchParams.set("lang", lang);
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`screening failed: HTTP ${res.status}`);
  return res.json();
}

/**
 * Turn a verdict into a decision your code can act on.
 * Note the default: anything we did not positively clear is NOT paid.
 * Fail-closed is the whole point — a screening call that fails open is theatre.
 */
function decide(result, { maxRiskToPay = 30 } = {}) {
  if (!result) return { pay: false, why: "no screening result — fail closed" };
  if (result.blocked || result.verdict === "risky") {
    return { pay: false, why: `flagged: ${(result.signals || [])[0] || result.verdict}` };
  }
  if (result.verdict === "caution" || (result.risk ?? 100) > maxRiskToPay) {
    return { pay: false, why: `risk ${result.risk}/100 above your threshold — send to human review` };
  }
  return { pay: true, why: "no risk signal (not the same as safe — enforce your mandate anyway)" };
}

// ── demo ────────────────────────────────────────────────────────────────────
const SAMPLES = [
  ["0x8589427373D6D84E98730D7795D8f6f8731FDA16", "a sanctioned mixer"],
  ["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "an ordinary address"],
];

const arg = process.argv[2];
const targets = arg ? [[arg, "your address"]] : SAMPLES;

for (const [addr, label] of targets) {
  const r = await screen(addr).catch((e) => { console.error(`  ${e.message}`); return null; });
  const d = decide(r);
  console.log(`\n${label}\n  ${addr}`);
  if (r) {
    console.log(`  verdict     ${r.verdict}  (risk ${r.risk}/100)`);
    console.log(`  signal_keys ${JSON.stringify(r.signal_keys || [])}   <- branch on these, not on prose`);
    if (r.evidence?.length) console.log(`  evidence    ${r.evidence.length} item(s), e.g. ${r.evidence[0].url || r.evidence[0].label}`);
  }
  console.log(`  DECISION    ${d.pay ? "PAY" : "DO NOT PAY"} — ${d.why}`);
}

console.log(`
Next steps
  SDK   npm i oceanalt-aml
  MCP   npx oceanalt-aml-mcp          (Claude / any MCP client calls it natively)
  Spec  https://oceanalt.com/en/rap   — and the conformance suite in this repo,
        which you can run against any implementation, including OceanAlt's own.
`);
