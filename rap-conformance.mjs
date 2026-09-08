#!/usr/bin/env node
/**
 * RAP Conformance Test Runner v1.0
 * ===========================================================================
 * RAP 一致性测试 —— 任何人都可以拿它去跑任何一个实现,包括跑 OceanAlt 自己。
 *
 * 用法 / Usage:
 *   node rap-conformance.mjs                          # 跑 OceanAlt(默认)
 *   node rap-conformance.mjs https://your-gateway.com  # 跑你自己的实现
 *   node rap-conformance.mjs https://... --json        # 输出 JSON
 *
 * 需要 Node 18+(用到内置 fetch),无任何依赖,不需要安装。
 *
 * 设计约束 / Design constraints:
 *   1. 向量只描述 HTTP 请求与对返回的断言,不引用任何 OceanAlt 内部概念 ——
 *      否则它就是我们的自测脚本,不是标准。
 *   2. 断言只写在能观察到的东西上。"有良好的风控文化"不是断言;
 *      "对制裁地址的返回里 decision 必须是 decline"是。
 *   3. 允许失败,且必须如实公布。一个自己给自己发满分的一致性套件,
 *      不比没有强。
 *
 * "符合 RAP" 的唯一定义:severity=critical 的向量全部通过。
 * important 未通过会如实列出,但不否定符合性。
 *
 * 本文件由 OceanAlt 从同一份源头自动生成(site/scripts/build-conformance-standalone.mjs),
 * 与 OceanAlt 线上每日自测跑的是同一份断言实现与同一批向量。
 * 生成时间 / Generated: 2026-09-08T16:46:19.368Z
 *
 * 公开跑分 / Public scoreboard: https://oceanalt.com/zh/rap/conformance
 * 规范 / Spec:                  https://oceanalt.com/zh/rap
 * License: MIT
 * ===========================================================================
 */

// ── 断言求值(与 OceanAlt 线上同一份实现)──────────────────────────
/**
 * 断言求值 —— 刻意写成纯 JS。
 *
 * 线上页面(TS)和命令行 runner(mjs)必须用【同一份】实现:
 * 一致性套件如果自己有两套"怎么算通过",它裁定别人的时候就没有立场。
 * 写成 .mjs 是为了让 runner 能直接 import,不必从 TS 源里正则剥类型
 * (试过,`cur as Record<string, unknown>` 这类断言一定会漏)。
 */

/** 点号路径取值,支持数组下标:"evidence.0.url"。 */
function pick(obj, path) {
  if (!path) return obj;
  let cur = obj;
  for (const seg of String(path).split(".")) {
    if (cur == null) return undefined;
    if (Array.isArray(cur)) {
      const i = Number(seg);
      cur = Number.isInteger(i) ? cur[i] : undefined;
    } else if (typeof cur === "object") {
      cur = cur[seg];
    } else {
      return undefined;
    }
  }
  return cur;
}

function evalAssertion(body, a) {
  const got = pick(body, a.path);
  switch (a.op) {
    case "equals": return { pass: got === a.value, got };
    case "oneOf": return { pass: Array.isArray(a.value) && a.value.includes(got), got };
    case "exists": return { pass: got !== undefined && got !== null, got };
    case "absent": return { pass: got === undefined || got === null, got };
    case "contains": return { pass: typeof got === "string" && got.includes(String(a.value)), got };
    case "gte": return { pass: typeof got === "number" && got >= Number(a.value), got };
    case "lte": return { pass: typeof got === "number" && got <= Number(a.value), got };
    case "typeOf": return { pass: typeof got === a.value, got };
    case "nonEmptyArray": return { pass: Array.isArray(got) && got.length > 0, got };
    default: return { pass: false, got };
  }
}


// ── 测试向量 v1.0(与 OceanAlt 线上同一批)────────────────────
const FIXTURES = {
  /** Tornado Cash 相关合约。曾在 OFAC SDN 名单上,2025-03-21 移除；混币器属性不变。 */
  mixer: "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
  /** vitalik.eth。长期活跃、无风险信号的公开地址。 */
  clean: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  /** 格式非法，用来验证输入校验不会被当成 clear 放过去。 */
  malformed: "0xnot-an-address",
};

const VECTORS = [
  // ── 支柱:AML 筛查 ────────────────────────────────────────────
  {
    id: "RAP-AML-01",
    pillar: "aml",
    severity: "critical",
    titleZh: "对已知混币器地址必须给出否定判决",
    titleEn: "A known mixer address must produce a negative decision",
    provesZh: "筛查真的在跑，而不是对所有地址一律放行。这是整个 RAP 里最容易造假、也最容易验证的一条。",
    provesEn: "Screening actually runs, rather than waving everything through. It is the easiest claim in RAP to fake and the easiest to check.",
    request: { method: "GET", path: "/api/decide", query: { to: FIXTURES.mixer } },
    assertions: [
      { path: "decision", op: "oneOf", value: ["decline", "review"], whyZh: "对已知混币器给 allow，说明筛查没起作用。", whyEn: "Allowing a known mixer means screening is not doing anything." },
      { path: "allow", op: "equals", value: false, whyZh: "布尔位必须和 decision 一致，否则 Agent 按哪个走都可能错。", whyEn: "The boolean must agree with decision, or an agent branching on either one can be wrong." },
    ],
  },
  {
    id: "RAP-AML-02",
    pillar: "aml",
    severity: "critical",
    titleZh: "筛查不可用时不得谎报为 clear",
    titleEn: "When screening is unavailable, the result must not be reported as clear",
    provesZh: "这是合规软件最危险的一种失败：数据源挂了，却返回「没查到风险」。静默的 PASS 比明确的错误糟得多。",
    provesEn: "This is the most dangerous failure mode in compliance software: the data source is down and the answer comes back as “no risk found”. A silent PASS is far worse than a loud error.",
    request: { method: "GET", path: "/api/decide", query: { to: FIXTURES.clean } },
    assertions: [
      { path: "verdict", op: "oneOf", value: ["clear", "caution", "risky", "uncertain"], whyZh: "判决必须落在明确的取值域里，uncertain 要能表达出来。", whyEn: "The verdict must come from a defined set, and uncertain must be expressible." },
      { path: "retry", op: "exists", whyZh: "拿不到结论时，Agent 需要知道该不该退避重试。", whyEn: "When there is no conclusion, the agent needs to know whether to back off and retry." },
    ],
  },
  {
    id: "RAP-AML-03",
    pillar: "aml",
    severity: "important",
    titleZh: "非法输入不得被当成通过",
    titleEn: "Malformed input must not be treated as a pass",
    provesZh: "把无法解析的地址当成「没有风险信号」，是同一个静默 PASS 问题的另一张脸。",
    provesEn: "Treating an unparseable address as “no risk signal” is the same silent-PASS problem wearing a different face.",
    request: { method: "GET", path: "/api/decide", query: { to: FIXTURES.malformed } },
    expectStatus: [400, 422],
    assertions: [
      { path: "error", op: "exists", whyZh: "必须明确报错，而不是返回一个看起来正常的 allow。", whyEn: "It must fail explicitly rather than return something that looks like a normal allow." },
    ],
  },

  // ── 支柱：可审计 ──────────────────────────────────────────────
  {
    id: "RAP-AUDIT-01",
    pillar: "audit",
    severity: "critical",
    titleZh: "判决必须附带可核验的证据，而不只是一个分数",
    titleEn: "A verdict must carry verifiable evidence, not just a score",
    provesZh: "分数是不可反驳的。证据可以被第三方点开、复核、推翻 —— 这正是「可审计」的含义。",
    provesEn: "A score cannot be argued with. Evidence can be opened, re-checked and overturned by a third party — which is what auditability means.",
    request: { method: "GET", path: "/api/decide", query: { to: FIXTURES.mixer } },
    assertions: [
      { path: "evidence", op: "nonEmptyArray", whyZh: "只给结论不给依据，读者无法自行核验，也无法反驳。", whyEn: "A conclusion without grounds cannot be checked or challenged by the reader." },
      { path: "evidence.0.url", op: "exists", whyZh: "证据要能点开到原始来源，不能只是我们自己的转述。", whyEn: "Evidence must link to the primary source, not merely paraphrase it." },
    ],
  },
  {
    id: "RAP-AUDIT-02",
    pillar: "audit",
    severity: "important",
    titleZh: "机器可读的原因码，而不是自由文本",
    titleEn: "Machine-readable reason codes, not free text",
    provesZh: "自由文本让 Agent 只能靠字符串匹配来理解拒绝原因 —— 换个措辞就全崩。",
    provesEn: "Free text forces an agent to string-match its way to understanding a refusal — one rewording and it all breaks.",
    request: { method: "GET", path: "/api/decide", query: { to: FIXTURES.mixer } },
    assertions: [
      { path: "reason_code", op: "typeOf", value: "string", whyZh: "原因码必须稳定、机读。", whyEn: "The reason code must be stable and machine-readable." },
      { path: "signal_class", op: "oneOf", value: ["ok", "payment", "regulatory", "authorization", "uncertain", "client_error"], whyZh: "分类决定 Agent 该不该重试，不能自由发挥。", whyEn: "The class decides whether an agent should retry; it cannot be improvised." },
    ],
  },

  // ── 支柱：授权与限额 ──────────────────────────────────────────
  {
    id: "RAP-MANDATE-01",
    pillar: "mandate",
    severity: "critical",
    titleZh: "超过限额的付款必须被真的拦下",
    titleEn: "A payment above the mandate ceiling must actually be blocked",
    provesZh: "这是 RAP 与「给模型写一段谨慎的提示词」之间的分界线。注意这条必须先设一个限额再测 —— 不设就只能看到那道闸 skip，而一道永远 skip 的闸能让任何实现「通过」。",
    provesEn: "This is the line between RAP and “write the model a careful prompt”. Note it must set a ceiling first: without one the gate merely skips, and a gate that always skips lets any implementation “pass”.",
    setup: [
      {
        method: "POST",
        path: "/api/pay",
        body: { action: "register", agentId: "rapconf-{{nonce}}", entity: "RAP conformance vector (automated)", mandate: { maxUsdc: 10, dailyUsdc: 20, purpose: "conformance" } },
        capture: { agentId: "agentId", secret: "agentSecret" },
      },
    ],
    request: {
      method: "POST",
      path: "/api/pay",
      headers: { "x-agent-secret": "{{secret}}" },
      body: { action: "preview", agentId: "{{agentId}}", amountUsdc: 999999, to: FIXTURES.clean, purpose: "conformance" },
    },
    assertions: [
      { path: "decision", op: "equals", value: "block", whyZh: "设了 10 USDC 的上限却放行 999999，说明限额只是文档里的一句话。", whyEn: "Letting 999999 through against a 10 USDC ceiling means the limit exists only in the documentation." },
      { path: "blocked", op: "equals", value: true, whyZh: "顶层要有一个明确的布尔位。只给 decision 字符串，Agent 容易读 ok 就走。", whyEn: "There must be an unambiguous boolean at the top level; with only a decision string an agent tends to branch on ok and proceed." },
      { path: "checks", op: "nonEmptyArray", whyZh: "必须逐闸给出结果，而不是一个笼统的通过/不通过。", whyEn: "It must report per-gate results, not one blanket pass/fail." },
    ],
    teardown: [
      { method: "POST", path: "/api/pay", headers: { "x-agent-secret": "{{secret}}" }, body: { action: "revoke", agentId: "{{agentId}}" } },
    ],
  },

  // ── 支柱：身份归因 ────────────────────────────────────────────
  {
    id: "RAP-KYA-01",
    pillar: "kya",
    severity: "important",
    titleZh: "服务能自述它跑了哪些控制",
    titleEn: "The service can describe which controls it runs",
    provesZh: "一个不肯说自己做了什么检查的合规服务，没法被审计，也没法被对手方评估。",
    provesEn: "A compliance service that will not say which checks it runs cannot be audited, nor assessed by a counterparty.",
    request: { method: "GET", path: "/api/pay" },
    assertions: [
      { path: "gates", op: "nonEmptyArray", whyZh: "自述清单是可审计性的入口。", whyEn: "The self-description is the entry point to auditability." },
    ],
  },

  // ── 支柱：互操作 ──────────────────────────────────────────────
  {
    id: "RAP-INTEROP-01",
    pillar: "interop",
    severity: "important",
    titleZh: "输出语言可协商，且提供语言无关的判定键",
    titleEn: "Output language is negotiable, and language-independent keys are provided",
    provesZh: "跨境的 Agent 支付里，人读的那句话是给人看的；Agent 该按键判断。只给一种语言的散文，等于把判定逻辑绑死在一种语言上。",
    provesEn: "In cross-border agent payments the human sentence is for humans; the agent should branch on keys. Prose in a single language ties decision logic to that language.",
    request: { method: "GET", path: "/api/risk", query: { addr: FIXTURES.mixer } },
    assertions: [
      { path: "signal_keys", op: "exists", whyZh: "没有语言无关的键，Agent 只能解析人话。", whyEn: "Without language-independent keys an agent has to parse prose." },
    ],
  },
  {
    id: "RAP-INTEROP-02",
    pillar: "interop",
    severity: "important",
    titleZh: "提供机器可发现的接口描述",
    titleEn: "A machine-discoverable interface description is published",
    provesZh: "「可被 Agent 调用」如果只体现在人读的文档里，那 Agent 得先学会读人话文档。",
    provesEn: "If “callable by agents” exists only in human documentation, the agent first has to learn to read human documentation.",
    request: { method: "GET", path: "/openapi.json" },
    assertions: [
      { path: "openapi", op: "typeOf", value: "string", whyZh: "OpenAPI 是 Agent 自动发现接口的通行做法。", whyEn: "OpenAPI is the common way for agents to discover an interface." },
      { path: "paths", op: "exists", whyZh: "光有版本号没有路径，等于没有。", whyEn: "A version with no paths is nothing." },
    ],
  },

  // ── 支柱：防火墙 ──────────────────────────────────────────────
  {
    id: "RAP-CONTROLS-01",
    pillar: "controls",
    severity: "critical",
    titleZh: "拒绝时必须给出可执行的下一步",
    titleEn: "A refusal must come with an actionable next step",
    provesZh: "只说「不行」的拒绝，会让自主 Agent 要么无脑重试、要么直接卡死。两种都不是我们想要的。",
    provesEn: "A refusal that only says “no” leaves an autonomous agent either retrying blindly or stuck. Neither is what we want.",
    request: { method: "GET", path: "/api/decide", query: { to: FIXTURES.mixer } },
    assertions: [
      { path: "retry", op: "exists", whyZh: "Agent 需要知道这次拒绝是不是可以通过改变什么来解决。", whyEn: "The agent needs to know whether the refusal can be resolved by changing something." },
      { path: "advice", op: "typeOf", value: "string", whyZh: "给规划器一句可读的下一步。", whyEn: "Give the planner one readable next step." },
    ],
  },

  // ── 支柱：隐私 ────────────────────────────────────────────────
  {
    id: "RAP-PRIVACY-01",
    pillar: "privacy",
    severity: "important",
    titleZh: "基础筛查不得强制要求注册或身份材料",
    titleEn: "Basic screening must not require signup or identity documents",
    provesZh: "合规不该以「先把你自己交出来」为前提。查一个公开地址的风险，不需要知道是谁在查。",
    provesEn: "Compliance should not be premised on “hand yourself over first”. Checking a public address's risk does not require knowing who is asking.",
    request: { method: "GET", path: "/api/risk", query: { addr: FIXTURES.clean } },
    expectStatus: [200],
    assertions: [
      { path: "verdict", op: "exists", whyZh: "不带任何凭证也应拿得到结论。", whyEn: "A result should come back with no credential presented at all." },
    ],
  },

  // ── 支柱：隐私 ────────────────────────────────────────────────
  {
    id: "RAP-PRIVACY-02",
    pillar: "privacy",
    severity: "important",
    titleZh: "匿名筛查不得给调用方种持久标识",
    titleEn: "Anonymous screening must not set a persistent identifier on the caller",
    provesZh: "一个只需回答「这地址风不风险」的接口，没有理由记住是谁问的。种 cookie 意味着在做与合规无关的采集。",
    provesEn: "An endpoint whose only job is to answer whether an address is risky has no reason to remember who asked. Setting a cookie means collecting something the compliance task does not need.",
    request: { method: "GET", path: "/api/risk", query: { addr: FIXTURES.clean } },
    assertions: [],
    responseHeaderAssertions: [
      { header: "set-cookie", op: "absent", whyZh: "匿名查询种 cookie = 过度采集。", whyEn: "A cookie on an anonymous query is over-collection." },
    ],
  },
  {
    id: "RAP-PRIVACY-03",
    pillar: "privacy",
    severity: "important",
    titleZh: "服务必须公开声明数据保留期限",
    titleEn: "The service must publicly state how long it retains data",
    provesZh: "「避免过度采集」如果不说保留多久，就是一句无法核验的话。接入方要评估把查询交给你的风险，首先得知道这些查询会被留多久。⚠️ 写下这条时，OceanAlt 自己不通过 —— 我们的保留政策还没定。放在这里不是为了好看，是为了让这个缺口有人盯着。",
    provesEn: "“We avoid over-collecting” is unverifiable without a retention period. Anyone deciding whether to send you their queries needs to know how long those queries live. ⚠️ At the time this vector was written OceanAlt does not pass it — our retention policy is not settled. It is here to keep that gap visible, not to look good.",
    request: { method: "GET", path: "/api/pay" },
    assertions: [
      { path: "data_retention", op: "exists", whyZh: "自述里必须能读到保留期限，而不是让人去翻法律页猜。", whyEn: "The retention period must be readable from the self-description, not guessed at from a legal page." },
    ],
  },

  // ── 支柱：互操作(补充)──────────────────────────────────────
  {
    id: "RAP-INTEROP-03",
    pillar: "interop",
    severity: "important",
    titleZh: "跨域可调用",
    titleEn: "Callable cross-origin",
    provesZh: "很多 Agent 跑在浏览器、扩展或沙箱里。不支持跨域，等于把它们整类排除在外 —— 而它们恰恰是最需要付款前查一下的那批。",
    provesEn: "Many agents run in a browser, an extension or a sandbox. Refusing cross-origin calls excludes that entire class — which is precisely the class that most needs to check before paying.",
    request: { method: "GET", path: "/api/risk", query: { addr: FIXTURES.clean } },
    assertions: [],
    responseHeaderAssertions: [
      { header: "access-control-allow-origin", op: "exists", whyZh: "没有 CORS 头，浏览器里的 Agent 根本调不动。", whyEn: "Without a CORS header an in-browser agent simply cannot call it." },
    ],
  },
  {
    id: "RAP-INTEROP-04",
    pillar: "interop",
    severity: "important",
    titleZh: "自述里的控制项要带稳定机器键，不能只有显示名",
    titleEn: "Self-described controls must carry stable machine keys, not only display names",
    provesZh: "显示名会翻译、会改措辞。机器拿显示名做逻辑，换一次文案就全崩 —— 这和 signal_keys 是同一条道理，只是换了个位置。",
    provesEn: "Display names get translated and reworded. Logic branching on a display name breaks the next time the copy changes — the same principle as signal_keys, one layer over.",
    request: { method: "GET", path: "/api/pay" },
    assertions: [
      { path: "gates", op: "nonEmptyArray", whyZh: "先得有自述清单。", whyEn: "There has to be a self-described list first." },
      { path: "gates.0.key", op: "typeOf", value: "string", whyZh: "每项要有语言无关的键。", whyEn: "Each entry needs a language-independent key." },
    ],
  },
];

// ── Runner ────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const JSON_OUT = args.includes("--json");
const BASE = (args.find((a) => a.startsWith("http")) || "https://oceanalt.com").replace(/\/+$/, "");

/** 把 {{变量}} 替换成 setup 捕获到的值。深拷贝,不改原向量。 */
function fill(v, vars) {
  if (typeof v === "string") return v.replace(/\{\{(\w+)\}\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  if (Array.isArray(v)) return v.map((x) => fill(x, vars));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x, vars)]));
  return v;
}

async function send(step, vars) {
  const st = fill(step, vars);
  const url = new URL(BASE + st.path);
  for (const [k, val] of Object.entries(st.query || {})) url.searchParams.set(k, val);
  const res = await fetch(url, {
    method: st.method,
    headers: { accept: "application/json", ...(st.body ? { "content-type": "application/json" } : {}), ...(st.headers || {}) },
    ...(st.body ? { body: JSON.stringify(st.body) } : {}),
  });
  const body = await res.json().catch(() => null);
  return { status: res.status, body, headers: res.headers };
}

async function runVector(v) {
  const started = Date.now();
  const vars = { nonce: Math.random().toString(36).slice(2, 10) };
  let status = 0, body = null, headers = null, transportError = "", setupError = "";

  try {
    for (const step of v.setup || []) {
      const r = await send(step, vars);
      if (r.status >= 400) { setupError = `setup step ${step.path} returned ${r.status}`; break; }
      for (const [name, path] of Object.entries(step.capture || {})) {
        const got = pick(r.body, path);
        if (got === undefined || got === null) { setupError = `setup step did not yield ${path}`; break; }
        vars[name] = got;
      }
      if (setupError) break;
    }
    if (!setupError) {
      const r = await send({ ...v.request, query: v.request.query }, vars);
      status = r.status; body = r.body; headers = r.headers;
    }
  } catch (e) {
    transportError = String(e).slice(0, 200);
  }

  // 收尾一定要跑,哪怕断言失败了 —— 不给被测方留垃圾
  for (const step of v.teardown || []) { try { await send(step, vars); } catch { /* ignore */ } }

  const checks = [];
  if (setupError) {
    checks.push({ kind: "setup", pass: false, got: setupError, whyZh: "前置步骤没跑通,这条向量没能真正测到东西。", whyEn: "Setup did not complete, so this vector did not actually test anything." });
  } else {
    if (v.expectStatus) {
      checks.push({ kind: "status", pass: v.expectStatus.includes(status), got: status, want: v.expectStatus.join(" | "),
        whyZh: "状态码不在预期集合内。", whyEn: "HTTP status is outside the expected set." });
    }
    for (const a of v.assertions) {
      const r = evalAssertion(body, a);
      checks.push({ kind: "assert", path: a.path, op: a.op, pass: r.pass, got: r.got, want: a.value, whyZh: a.whyZh, whyEn: a.whyEn });
    }
    for (const h of v.responseHeaderAssertions || []) {
      const got = headers ? headers.get(h.header) : null;
      const pass = h.op === "exists" ? got != null
        : h.op === "absent" ? got == null
        : typeof got === "string" && got.includes(String(h.value));
      checks.push({ kind: "header", path: `header:${h.header}`, op: h.op, pass, got, want: h.value, whyZh: h.whyZh, whyEn: h.whyEn });
    }
  }

  const pass = !transportError && !setupError && checks.every((c) => c.pass);
  return { id: v.id, pillar: v.pillar, severity: v.severity, titleZh: v.titleZh, titleEn: v.titleEn, pass, status, ms: Date.now() - started, transportError, checks };
}

const results = [];
for (const v of VECTORS) results.push(await runVector(v));

const passed = results.filter((r) => r.pass).length;
const failedCritical = results.filter((r) => !r.pass && r.severity === "critical");
const summary = {
  vectorsVersion: "1.0",
  base: BASE,
  ranAt: new Date().toISOString(),
  total: results.length,
  passed,
  failed: results.length - passed,
  criticalFailed: failedCritical.length,
  conformant: failedCritical.length === 0,
};

if (JSON_OUT) {
  console.log(JSON.stringify({ summary, results }, null, 2));
} else {
  console.log(`RAP conformance v1.0 · implementation under test: ${BASE}`);
  console.log("");
  for (const r of results) {
    const mark = r.pass ? "PASS" : r.severity === "critical" ? "FAIL" : "warn";
    console.log(`  ${mark}  ${r.id}  ${r.titleEn}  (${r.status || "no response"}, ${r.ms}ms)`);
    if (!r.pass) {
      if (r.transportError) console.log(`         request failed: ${r.transportError}`);
      for (const c of r.checks.filter((x) => !x.pass)) {
        const at = c.kind === "status" ? "HTTP status" : `${c.path} (${c.op})`;
        console.log(`         ${at} → got ${JSON.stringify(c.got)}${c.want !== undefined ? `, want ${JSON.stringify(c.want)}` : ""}`);
        console.log(`         why it matters: ${c.whyEn}`);
      }
    }
  }
  console.log("");
  console.log(`${passed}/${results.length} passed; ${failedCritical.length} critical failure(s) → ${summary.conformant ? "CONFORMANT with RAP v1.0" : "NOT conformant (critical failures)"}`);
}

// critical 有失败就非零退出 —— 可以直接当 CI 门禁用
process.exit(failedCritical.length ? 1 : 0);
