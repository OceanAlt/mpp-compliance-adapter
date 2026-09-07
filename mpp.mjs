// OceanAlt × MPP(Machine Payments Protocol,Stripe/Tempo)合规适配器 — v0.1(B31,2026-09-06)
// ─────────────────────────────────────────────────────────────────────────
// MPP 核心把「谁在付、被谁授权、付前拦、付后可核」全留成空位,但给了标准化挂点:
//   · Credential 里的 `source`(付款方标识,建议 did:pkh)—— 我们从这里拿到要筛查的地址
//   · 核心 §4.2:"payment verified, but policy denies access" → 403(RFC 9457 problem+json)
//   · 核心 §9.3:Challenge 可带自定义参数,客户端必须忽略未知参数 → 我们加 `compliance` 参数公告策略
//   · Receipt 的用途明写 Auditing / Dispute / Reconciliation → 我们在成功响应上附 `Payment-Compliance` 头
// 这份适配器是【HTTP 层的 drop-in】:不依赖 mppx 内部实现,包在任何 `(Request) => Response` 处理器外面即可。
// 规范草案:docs/mpp/draft-payment-compliance-00.md(companion,不动核心)。
//
// 诚实边界:同 core.mjs —— 这是合规风险筛查信号,不是"完整 AML 认证";拿不到结论 = UNCERTAIN(fail-closed)。

import { screenAddress } from "./core.mjs";

export const MPP_ADAPTER_VERSION = "0.1.0";
export const PROBLEM_TYPE_DENIED = "https://oceanalt.com/rap/problems/compliance-denied";
export const PROBLEM_TYPE_UNCERTAIN = "https://oceanalt.com/rap/problems/compliance-uncertain";
export const CHALLENGE_PARAM = "compliance";
export const RESPONSE_HEADER = "Payment-Compliance";

// did:pkh:eip155:<chainId>:<address> → 我们支持的链名(core 的 network 参数)
const CHAIN_TO_NETWORK = { 1: "ethereum", 8453: "base", 137: "polygon", 42161: "arbitrum", 10: "optimism", 56: "bsc", 43114: "avalanche" };

// ── 编码小工具:JCS 风格(键排序)+ base64url ─────────────────────────────────
export function canonicalize(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
}
export const b64url = (s) => Buffer.from(typeof s === "string" ? s : canonicalize(s), "utf8").toString("base64url");
export const fromB64url = (s) => { try { return JSON.parse(Buffer.from(String(s || ""), "base64url").toString("utf8")); } catch { return null; } };

// ── 1. 解析 `Authorization: Payment <base64url JSON>` ──────────────────────
/** @returns {{challenge:object, source:string, payload:object}|null} */
export function parsePaymentAuthorization(headerValue) {
  const m = /^\s*Payment\s+([A-Za-z0-9_-]+=*)\s*$/i.exec(String(headerValue || ""));
  if (!m) return null;
  const cred = fromB64url(m[1]);
  if (!cred || typeof cred !== "object" || !cred.challenge || !cred.payload) return null;
  return { challenge: cred.challenge, source: String(cred.source || ""), payload: cred.payload };
}

// ── 2. 从 `source`(付款方标识)得到要筛查的地址与链 ────────────────────────────
/** did:pkh:eip155:8453:0xabc… → { address, chainId, network };其它形式 → address=null(筛不了 → UNCERTAIN) */
export function payerFromSource(source) {
  const m = /^did:pkh:eip155:(\d+):(0x[0-9a-fA-F]{40})$/.exec(String(source || "").trim());
  if (m) { const chainId = Number(m[1]); return { address: m[2], chainId, network: CHAIN_TO_NETWORK[chainId] || null, did: source }; }
  const raw = /^(0x[0-9a-fA-F]{40})$/.exec(String(source || "").trim());
  if (raw) return { address: raw[1], chainId: null, network: null, did: "" };
  return { address: null, chainId: null, network: null, did: String(source || "") };
}

// ── 3. 403 问题详情(RFC 9457)——「payment verified, but policy denies access」──
export function toMppProblem(ev, { retry = false, challengeId = "" } = {}) {
  const uncertain = ev.decision === "UNCERTAIN";
  const body = {
    type: uncertain ? PROBLEM_TYPE_UNCERTAIN : PROBLEM_TYPE_DENIED,
    title: uncertain ? "Compliance screening could not reach a conclusion" : "Compliance policy denies settlement",
    status: 403,
    detail: uncertain
      ? "The payment credential is valid, but the payer could not be screened (fail-closed). Retry later or contact the resource server."
      : `The payment credential is valid, but the payer did not pass compliance screening (${ev.reason_code}). The payment was not settled.`,
    decision: ev.decision, reason_code: ev.reason_code, score: ev.score,
    provider: ev.provider, provider_url: ev.provider_url,
    evidence_uri: ev.evidence_uri, evaluated_at: ev.evaluated_at, ttl_seconds: ev.ttl_seconds,
    subject: ev.subject, basis: ev.basis,
    retry: !!retry,
    ...(challengeId ? { challenge_id: challengeId } : {}),
  };
  const headers = { "content-type": "application/problem+json", "cache-control": "no-store" };
  if (retry) headers["retry-after"] = "30";
  return { status: 403, headers, body };
}

// ── 4. 成功响应上的 `Payment-Compliance` 头(base64url JCS JSON)—— 给收据审计用 ──
export function toPaymentComplianceHeader(ev, { challengeId = "", subject = "" } = {}) {
  return b64url({
    v: "rap-1.0", decision: ev.decision, reason_code: ev.reason_code, score: ev.score,
    provider: ev.provider, provider_url: ev.provider_url, evidence_uri: ev.evidence_uri,
    evaluated_at: ev.evaluated_at, expires_at: ev.expires_at, ttl_seconds: ev.ttl_seconds,
    subject: subject || ev.subject?.address || "", challenge_id: challengeId,
  });
}

// ── 5. 402 Challenge 上追加 `compliance` 参数(公告:我会在结算前筛付款方)────────
// 核心 §9.3:未知参数客户端必须忽略;它不在 HMAC 绑定序列里,所以追加不破坏服务端的挑战校验。
export function withComplianceChallenge(response, { policyUri = "https://oceanalt.com/en/rap", screen = ["payer"], level = "L1", provider = "https://oceanalt.com" } = {}) {
  if (!response || response.status !== 402) return response;
  const h = new Headers(response.headers);
  const wa = h.get("www-authenticate") || "";
  if (!/^\s*Payment\b/i.test(wa) || /\bcompliance=/.test(wa)) return response;
  const param = b64url({ v: "rap-1.0", policy: policyUri, screen, level, provider });
  h.set("www-authenticate", `${wa.trim()}, ${CHALLENGE_PARAM}="${param}"`);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
}

// ── 6. drop-in 网关:包在任何 MPP 资源处理器外面 ────────────────────────────────
/**
 * @param {(req: Request) => Promise<Response>|Response} handler  你的 MPP 资源处理器(mppx.charge(...)(req) 或任何等价物)
 * @param {object} opts
 * @param {boolean} [opts.blockUncertain=true]  拿不到结论是否拦(默认 fail-closed:拦,并给 retry:true)
 * @param {string}  [opts.network]              强制指定链(不给则从 did:pkh 的 chainId 推)
 * @param {string}  [opts.baseUrl]              OceanAlt 基址(测试用)
 * @param {(info:{ev:object, payer:object, challengeId:string, action:string}) => void} [opts.onDecision]  审计回调
 * @param {object}  [opts.challenge]            给 402 追加 compliance 参数的选项;传 false 关闭
 */
export function complianceGate(handler, opts = {}) {
  const { blockUncertain = true, network, baseUrl, onDecision, challenge = {} } = opts;
  return async function gated(request) {
    const auth = request.headers.get("authorization") || "";
    const cred = parsePaymentAuthorization(auth);
    if (!cred) {
      // 没带凭证:交给处理器发 402;顺手在 Challenge 上公告策略
      const res = await handler(request);
      return challenge === false ? res : withComplianceChallenge(res, challenge);
    }
    const payer = payerFromSource(cred.source);
    const challengeId = String(cred.challenge?.id || "");
    let ev;
    if (payer.address) {
      ev = await screenAddress(payer.address, { network: network || payer.network || "ethereum", baseUrl });
    } else {
      ev = { decision: "UNCERTAIN", reason_code: "PAYER_UNSCREENABLE", score: null, null_reason: "source is not a screenable did:pkh/eip155 identifier", provider: "OceanAlt", provider_url: "https://oceanalt.com", evidence_uri: "", evaluated_at: new Date().toISOString(), ttl_seconds: 0, expires_at: "", subject: { address: null, network: "", did: payer.did }, basis: [] };
    }
    const deny = ev.decision === "FAIL" || (blockUncertain && ev.decision === "UNCERTAIN");
    if (deny) {
      const p = toMppProblem(ev, { retry: ev.decision === "UNCERTAIN", challengeId });
      onDecision?.({ ev, payer, challengeId, action: "deny" });
      return new Response(JSON.stringify(p.body), { status: p.status, headers: p.headers });
    }
    const res = await handler(request);
    onDecision?.({ ev, payer, challengeId, action: res.ok ? "settle" : "handler-" + res.status });
    if (!res.ok) return res;
    const h = new Headers(res.headers);
    h.set(RESPONSE_HEADER, toPaymentComplianceHeader(ev, { challengeId, subject: payer.did || payer.address || "" }));
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
  };
}
