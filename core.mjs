// OceanAlt 协议无关合规核心 (protocol-agnostic compliance core) — v1.0
// ─────────────────────────────────────────────────────────────────────────
// 一句话:把 OceanAlt 的合规风险筛查(/api/risk)做成【一次筛查、一个规范对象、多协议消费】。
// 设计动机:不押注单一协议(x402)被采纳,而是把同一份可核验的筛查结论,
//           通过 adapters.mjs 里的纯映射函数翻译成【每个 agent 支付/信任协议】的原生形状。
//
// 规范对象 CanonicalEvaluation(所有适配器的唯一输入)= x402 v0.2 TrustEvaluation 的超集:
//   subject / decision(PASS|FAIL|UNCERTAIN) / score(0..1 可空+null_reason) /
//   reason_code / basis[](结构化可核验证据) / category / evidenceType / direction /
//   evidence_uri / ttl_seconds / issued_at / expires_at
//
// 诚实边界(不过度承诺,见仓库 AGENTS.md「不许伪造数据」):
//   这是「compliance risk screening(合规风险筛查)」信号——命中制裁/混币器/诈骗名单、
//   发行方(USDT/USDC)冻结、链上启发式风险,并给可点开自核的证据。
//   它【不是】「完整 AML 合规认证」;PASS = 本提供方未发现拦截理由,【不等于】绝对安全;
//   拿不到结论一律 UNCERTAIN(fail-closed),score=null,绝不编造分数放行。

export const CORE_SCHEMA = "oceanalt-compliance/1.0";
export const CORE_VERSION = "1.0.0";
export const DEFAULT_BASE = "https://oceanalt.com";

/**
 * @typedef {"PASS"|"FAIL"|"UNCERTAIN"} Decision
 * @typedef {Object} Basis
 * @property {string} class    // "regulatory"
 * @property {string} kind     // sanctions-list|mixer-list|issuer-freeze|onchain-taint|onchain-heuristic|intel-db
 * @property {string} source
 * @property {string} ref
 * @property {string} url
 * @property {string} detail
 * @property {string} observed_at
 *
 * @typedef {Object} CanonicalEvaluation
 * @property {string} schema @property {string} version
 * @property {string} provider @property {string} provider_url
 * @property {"compliance"} category @property {"regulatory"} evidenceType @property {string} direction
 * @property {{address:string|null,network:string,verdict?:string,risk?:number|null}} subject
 * @property {Decision} decision
 * @property {number|null} score        // 0..1,1=最可信(=1-risk/100);未知=null
 * @property {string} [null_reason]
 * @property {string} reason_code
 * @property {Basis[]} basis
 * @property {string} evidence_uri
 * @property {number} ttl_seconds @property {string} issued_at @property {string} expires_at @property {string} evaluated_at
 */

// evidence[] → 结构化 basis[](class/kind/source/ref/url/detail/observed_at)。每条可寻址、可核验。
function toBasis(r, observed_at) {
  const ev = Array.isArray(r?.evidence) ? r.evidence : [];
  return ev.map((e) => ({
    class: "regulatory",
    kind: /冻结|frozen|blacklist/i.test(e.label || "") ? "issuer-freeze"
      : /制裁|sanction|OFAC/i.test(e.label || "") ? "sanctions-list"
      : /混币|mixer|Tornado/i.test(e.label || "") ? "mixer-list"
      : /沾染|taint/i.test(e.label || "") ? "onchain-taint"
      : /情报|intel/i.test(e.label || "") ? "intel-db"
      : "onchain-heuristic",
    source: e.source || "OceanAlt",
    ref: e.url || "",
    url: e.url || "",
    detail: String(e.detail || e.label || "").slice(0, 300),
    observed_at,
  }));
}

// verdict → Decision(fail-closed:拿不到结论一律 UNCERTAIN,绝不静默 PASS)
function mapDecision(verdict) {
  if (verdict === "risky") return "FAIL";
  if (verdict === "clear") return "PASS";
  return "UNCERTAIN";
}

function reasonCode(r) {
  const s = (r?.signals || []).join(" ");
  if (/制裁|sanction|OFAC/i.test(s)) return "SANCTIONS_MATCH";
  if (/混币|mixer|Tornado/i.test(s)) return "MIXER_TAINT";
  if (/冻结|frozen|blacklist/i.test(s)) return "ISSUER_FROZEN";
  if (/沾染|taint/i.test(s)) return "ONCHAIN_TAINT";
  if (r?.verdict === "risky") return "ONCHAIN_HIGH_RISK";
  if (r?.verdict === "caution") return "RISK_SIGNALS_PRESENT";
  if (r?.verdict === "clear") return "NO_RISK_SIGNAL"; // 未见信号 ≠ 绝对安全
  return "SCREENING_UNAVAILABLE";
}

/**
 * 【唯一事实来源】对一个地址做一次合规筛查,返回协议无关的 CanonicalEvaluation。fail-closed。
 * @param {string|null} address
 * @param {{ baseUrl?:string, network?:string, direction?:string, ttlSeconds?:number, timeoutMs?:number }} [opts]
 * @returns {Promise<CanonicalEvaluation>}
 */
export async function screenAddress(address, opts = {}) {
  const baseUrl = (opts.baseUrl || DEFAULT_BASE).replace(/\/$/, "");
  const network = opts.network || "";
  const ttl = opts.ttlSeconds ?? 3600; // 保守 1h(制裁名单可能更新)
  const issued_at = new Date().toISOString();
  const expires_at = new Date(Date.now() + ttl * 1000).toISOString();
  const direction = opts.direction || "payee"; // 合规筛查看【资金对手方/收款方】,非付款方行为
  const q = new URLSearchParams({ addr: String(address || "") });
  if (network) q.set("network", network);
  const evidence_uri = `${baseUrl}/api/risk?${q.toString()}`;

  const base = {
    schema: CORE_SCHEMA, version: CORE_VERSION, provider: "OceanAlt", provider_url: baseUrl,
    category: "compliance", evidenceType: "regulatory", direction,
    evidence_uri, ttl_seconds: ttl, issued_at, expires_at, evaluated_at: issued_at,
    subject: { address: address || null, network: network || "auto" },
  };
  const uncertain = (null_reason, reason_code = "SCREENING_UNAVAILABLE") =>
    ({ ...base, decision: "UNCERTAIN", score: null, null_reason, reason_code, basis: [] });
  if (!address) return uncertain("no address provided", "NO_ADDRESS");

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 12000);
    const res = await fetch(evidence_uri, { signal: ctrl.signal, headers: { accept: "application/json" } }).finally(() => clearTimeout(t));
    if (!res.ok) return uncertain(`upstream screening unavailable (HTTP ${res.status})`);
    const r = await res.json();
    const hasRisk = Number.isFinite(r.risk);
    const score = hasRisk ? +(1 - Math.min(100, Math.max(0, r.risk)) / 100).toFixed(2) : null;
    return {
      ...base,
      decision: mapDecision(r.verdict), // FAIL 仅来自 risky(命中制裁/混币/冻结/沾染=足够强证据)
      score,
      ...(score === null ? { null_reason: "upstream returned no risk value" } : {}),
      reason_code: reasonCode(r),
      basis: toBasis(r, issued_at),
      subject: { address, network: network || "auto", verdict: r.verdict, risk: r.risk ?? null },
    };
  } catch {
    return uncertain("screening request failed (network/timeout)"); // fail-closed
  }
}

export default screenAddress;
