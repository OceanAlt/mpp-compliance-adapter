// OceanAlt × MPP 合规适配器 — 可跑 demo(实打 oceanalt.com /api/risk;凭证是【合成的测试凭证】,只为演示解析与网关行为)
// 跑法:node mpp-demo.mjs
// 证明三件事:① 没凭证 → 402 上多了 compliance 参数;② 干净付款方 → 放行且带 Payment-Compliance 头;③ 制裁付款方 → 403 problem+json,不结算。

import { complianceGate, b64url, parsePaymentAuthorization, payerFromSource, fromB64url } from "./mpp.mjs";

// 一个最小的"MPP 资源处理器":没 Authorization 就发 402 Challenge;有就当作已验证通过并返回资源。
// (真实场景里这一层是 mppx.charge(...)(request) —— 它负责验签与结算;本 demo 不碰任何链。)
const CHALLENGE = { id: "ch_demo_0001", realm: "demo.oceanalt.com", method: "tempo", intent: "charge", request: b64url({ amount: "0.10", currency: "USDC", recipient: "0x93c6…" }) };
async function resourceHandler(req) {
  if (!req.headers.get("authorization")) {
    const wa = `Payment id="${CHALLENGE.id}", realm="${CHALLENGE.realm}", method="${CHALLENGE.method}", intent="${CHALLENGE.intent}", request="${CHALLENGE.request}"`;
    return new Response(JSON.stringify({ error: "payment required" }), { status: 402, headers: { "www-authenticate": wa, "content-type": "application/json" } });
  }
  return new Response(JSON.stringify({ data: "premium resource", settled: "SIMULATED — no real settlement in this demo" }), { status: 200, headers: { "content-type": "application/json", "payment-receipt": b64url({ status: "success", method: "tempo", timestamp: new Date().toISOString(), reference: "sim-0001" }) } });
}

const gated = complianceGate(resourceHandler, { blockUncertain: true, onDecision: (i) => console.log(`   [audit] action=${i.action} decision=${i.ev.decision} reason=${i.ev.reason_code} payer=${i.payer.address || i.payer.did}`) });

// 合成测试凭证(仅用于演示解析;签名字段是占位,不代表任何真实交易)
const credential = (source) => "Payment " + b64url({ challenge: CHALLENGE, source, payload: { type: "proof", signature: "0xDEMO_PLACEHOLDER_NOT_A_REAL_SIGNATURE" } });

console.log("═══ OceanAlt × MPP 合规网关 demo(实打 /api/risk;凭证合成)═══\n");

console.log("① 无凭证 → 期望 402,且 WWW-Authenticate 上追加 compliance 参数");
{
  const r = await gated(new Request("https://demo.oceanalt.com/resource"));
  const wa = r.headers.get("www-authenticate") || "";
  const param = /compliance="([^"]+)"/.exec(wa)?.[1];
  console.log(`   status=${r.status}  compliance=${JSON.stringify(fromB64url(param))}\n`);
}

console.log("② 干净付款方(vitalik.eth,以太坊)→ 期望放行 200 + Payment-Compliance 头");
{
  const src = "did:pkh:eip155:1:0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
  console.log(`   解析:${JSON.stringify(payerFromSource(parsePaymentAuthorization(credential(src)).source))}`);
  const r = await gated(new Request("https://demo.oceanalt.com/resource", { headers: { authorization: credential(src) } }));
  console.log(`   status=${r.status}  Payment-Compliance=${JSON.stringify(fromB64url(r.headers.get("payment-compliance")))}\n`);
}

console.log("③ 制裁/混币器付款方(Tornado Cash 路由合约)→ 期望 403 application/problem+json,不结算");
{
  const src = "did:pkh:eip155:1:0x8589427373d6d84e98730d7795d8f6f8731fda16";
  const r = await gated(new Request("https://demo.oceanalt.com/resource", { headers: { authorization: credential(src) } }));
  const body = await r.json();
  console.log(`   status=${r.status}  content-type=${r.headers.get("content-type")}`);
  console.log(`   problem: type=${body.type}\n            reason_code=${body.reason_code} decision=${body.decision} retry=${body.retry}\n            evidence_uri=${body.evidence_uri}\n`);
}

console.log("④ 付款方标识不可筛(非 did:pkh)→ 期望 403 + retry:true(fail-closed,绝不静默放行)");
{
  const r = await gated(new Request("https://demo.oceanalt.com/resource", { headers: { authorization: credential("did:web:someone.example") } }));
  const body = await r.json();
  console.log(`   status=${r.status}  type=${body.type} reason=${body.reason_code} retry=${body.retry} retry-after=${r.headers.get("retry-after")}\n`);
}
console.log("完。以上所有 decision 都来自 oceanalt.com/api/risk 的真实筛查;凭证与结算是合成/模拟的,demo 不碰链。");
