import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { BrowserSecurityRuntime } from '../../checkout-web/src/browser-security.mjs';
import { demoHeaders } from './bridge.mjs';
import { demoScenarios, demoProfiles } from './demo.mjs';

const publicRoot = fileURLToPath(new URL('../../checkout-web/public/', import.meta.url));
const security = new BrowserSecurityRuntime({ publicRoot,
  manifestPath: fileURLToPath(new URL('../../checkout-web/security/script-allowlist.json', import.meta.url)) });
const script = readFileSync(new URL('./demo.mjs', import.meta.url));
const sri = `sha384-${createHash('sha384').update(script).digest('base64')}`;
const styles = readFileSync(new URL('../../checkout-web/public/styles.css', import.meta.url));

export function demoAsset(path) {
  if (path === '/demo.mjs') return { bytes: script, type: 'text/javascript; charset=utf-8' };
  if (path === '/checkout.mjs') return { bytes: security.verifyScript(path), type: 'text/javascript; charset=utf-8' };
  if (path === '/styles.css') return { bytes: styles, type: 'text/css; charset=utf-8' };
  return null;
}

export function renderDemoPage() {
  const nonce = randomBytes(18).toString('base64url');
  return {
    headers: { ...demoHeaders, 'content-type': 'text/html; charset=utf-8',
      'content-security-policy': ["default-src 'none'", "base-uri 'none'", "frame-ancestors 'none'",
        "form-action 'self'", "connect-src 'self'", "img-src 'self'", "frame-src 'none'",
        `script-src 'nonce-${nonce}' 'strict-dynamic'`, `style-src 'self' 'nonce-${nonce}'`,
        "require-trusted-types-for 'script'", "trusted-types elmpay-checkout"].join('; ') },
    html: `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ElmPay · 免费演示</title>
<style nonce="${nonce}">
:root{--ink:#18392f;--muted:#52675e;--surface:#ffffff;--brand:#155b43;--warning:#765300;--warning-bg:#fff5d4;--danger:#9d2833;
font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:var(--ink);background:#f2f6f3;font-synthesis:none}
*{box-sizing:border-box}body{margin:0;padding:clamp(16px,3vw,40px);font-size:16px;line-height:1.65}
.shell{max-width:1120px;margin:auto}header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:28px}
.brand{font-size:24px;font-weight:750;letter-spacing:-.7px;display:flex;align-items:center;gap:10px}.brand-mark{display:grid;place-items:center;background:var(--brand);color:white;width:38px;height:38px;border-radius:12px;font-size:26px}
.pill{font-size:13px;border:1px solid #b5cdbf;border-radius:30px;padding:6px 13px;background:#e8f3ec;font-weight:650}
.safety{background:var(--warning-bg);color:var(--warning);border:1px solid #ddca84;border-radius:14px;padding:16px 20px;font-size:14px}
.safety strong{display:block;font-size:15px;margin-bottom:3px}.hero{padding:28px 0 20px}h1{font-size:clamp(26px,3.3vw,38px);line-height:1.25;letter-spacing:-1px;margin:0 0 12px}
.hero p{margin:0;max-width:650px;color:var(--muted)}.steps{display:flex;list-style:none;padding:0;margin:10px 0 30px;gap:12px;font-size:14px}
.steps li{display:flex;align-items:center;gap:9px;flex:1;color:var(--muted);padding:10px 0;border-bottom:2px solid #cad9cf}.steps li[aria-current]{color:var(--brand);border-color:var(--brand);font-weight:700}
.step-number{width:26px;height:26px;display:grid;place-items:center;border:1px solid currentColor;border-radius:50%;font-size:12px;flex-shrink:0}
.layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,320px);gap:24px;align-items:start}.panel{background:var(--surface);border:1px solid #d5e2d9;border-radius:20px;padding:clamp(22px,3vw,34px);box-shadow:0 10px 35px #18392f05;min-width:0}
.eyebrow{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1.4px;color:var(--brand);margin:0 0 10px}h2{font-size:25px;line-height:1.35;margin:0 0 10px;letter-spacing:-.5px}p{margin:0 0 18px}.muted{color:var(--muted);font-size:14px}
label,select,button{font:inherit}label[for=scenario]{display:block;font-weight:650;margin:25px 0 8px}select{width:100%;background:var(--surface);color:var(--ink);border:1px solid #74897c;border-radius:10px;padding:12px;min-height:48px}
button,.link-button{min-height:48px;border-radius:10px;font-weight:650;padding:12px 18px;display:inline-flex;justify-content:center;align-items:center;line-height:1.4;text-align:center}
button{border:1px solid transparent;background:var(--brand);color:var(--surface);cursor:pointer}button:hover:not(:disabled){background:#104632}button:disabled{background:#64796d;color:white;cursor:default}.primary{width:100%;margin-top:12px}
.secondary{border:1px solid #74897c;background:white;color:var(--ink)}.secondary:hover:not(:disabled){background:#edf4ef}.link-button{border:1px solid #74897c;text-decoration:none;margin-top:12px;width:100%;color:var(--brand);background:white}
a{color:var(--brand);text-underline-offset:3px}:focus-visible{outline:3px solid #6646d1;outline-offset:4px}.skip-link{position:absolute;left:20px;top:-100px;background:white;padding:12px;z-index:10}.skip-link:focus{top:12px}
.helper{font-size:14px;color:var(--muted);margin:10px 0 20px;min-height:46px}.state-copy{padding:18px;border:1px solid #cad9cf;border-radius:12px;background:#f3f7f4;margin:20px 0}.state-copy p:last-child{margin:0}
[data-tone=success] .state-copy{background:#e5f5eb;border-color:#92bda1}[data-tone=warning] .state-copy{background:var(--warning-bg);border-color:#ddca84}[data-tone=danger] .state-copy{background:#fff0f0;border-color:#dbb6b8}
#amount{font-size:32px;font-weight:750;letter-spacing:-1px;margin:20px 0}fieldset{border:1px solid #74897c;border-radius:12px;padding:14px 18px;margin:20px 0}legend{font-size:14px;padding:0 5px;color:var(--muted)}fieldset label{display:flex;align-items:center;gap:12px;min-height:48px;font-weight:600}input[type=radio]{width:20px;height:20px;accent-color:var(--brand);flex-shrink:0}
#status{font-weight:650;font-size:15px;margin-bottom:8px}#error{color:var(--danger);font-size:14px;margin:16px 0}#create-status{font-size:14px;margin:14px 0 0}.summary{position:sticky;top:24px}.summary h2{font-size:18px;letter-spacing:0}.item{display:flex;gap:14px;align-items:center;margin:22px 0}.item-mark{background:#e8f3ec;border-radius:12px;display:grid;place-items:center;width:46px;height:46px;font-size:22px;flex-shrink:0}.item p{margin:0;font-size:14px}.item small{color:var(--muted)}
dl{margin:20px 0;border-top:1px solid #d5e2d9;padding-top:18px}dl div{display:flex;justify-content:space-between;gap:16px;margin:9px 0}dt{color:var(--muted);font-size:14px}dd{margin:0;font-weight:600}.total{border-top:1px solid #d5e2d9;padding-top:16px!important;margin-top:18px!important}.total dd{font-size:25px;letter-spacing:-.7px}.summary-note{font-size:13px;color:var(--muted);margin-bottom:0}.status-footer{font-size:13px;color:var(--muted);margin:24px 0 0}details{margin-top:20px;border-top:1px solid #d5e2d9;padding-top:15px;font-size:14px;color:var(--muted)}summary{cursor:pointer;min-height:44px;display:list-item;padding:8px 0;color:var(--brand);font-weight:600}details p{margin:8px 0}footer{text-align:center;color:var(--muted);font-size:13px;padding:26px 8px}footer p{margin:0}
[hidden]{display:none!important}@media(max-width:760px){.layout{grid-template-columns:1fr}.summary{position:static}.steps{gap:9px;font-size:12px}.steps li{gap:6px}.hero{padding-top:24px}.panel{border-radius:16px}.brand{font-size:22px}.pill{font-size:12px}.safety{padding:14px 16px}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important}}
</style><script type="module" src="/demo.mjs" nonce="${nonce}" integrity="${sri}" crossorigin="anonymous"></script>
</head><body><a class="skip-link" href="#main">跳到演示内容</a><div class="shell">
<header><div class="brand"><span class="brand-mark" aria-hidden="true">e</span>ElmPay</div><span class="pill">免费体验 · 演示模式</span></header>
<aside class="safety" role="note"><strong>免费演示 · 真实支付已禁用</strong>
所有金额和支付结果均为模拟数据，不发生真实扣款。请勿输入真实卡号、密码、商户密钥或个人信息。</aside>
<div class="hero"><h1>一笔演示订单，完整体验收银台</h1><p>从创建订单到确认结果，体验清晰的支付流程。所有结果由演示服务确认，全程不扣款。</p></div>
<ol class="steps" aria-label="演示进度"><li data-step="create" aria-current="step"><span class="step-number" aria-hidden="true">1</span>创建订单</li><li data-step="confirm"><span class="step-number" aria-hidden="true">2</span>确认模拟支付</li><li data-step="result"><span class="step-number" aria-hidden="true">3</span>查看结果</li></ol>
<main id="main" class="layout" tabindex="-1"><div class="panel">
<section id="demo-start" aria-labelledby="create-title"><p class="eyebrow">Start a demo</p><h2 id="create-title">选择一个模拟场景</h2><p class="muted">成功、拒绝或待确认，体验不同结果下的收银台。</p>
<label for="demo-method">模拟支付方式</label><select id="demo-method" aria-describedby="method-description">${demoProfiles.map(value => `<option value="${value.method}">${value.label} · ${value.displayAmount}</option>`).join('')}</select>
<p id="method-description" class="helper">本地模拟，不连接微信，不生成真实支付二维码，不发生真实扣款。</p>
<label for="scenario">模拟结果</label><select id="scenario" aria-describedby="scenario-description">${demoScenarios.map(value => `<option value="${value.id}">${value.label}</option>`).join('')}</select>
<p id="scenario-description" class="helper">${demoScenarios[0].hint}</p>
<button id="create-demo" class="primary" type="button">创建演示订单</button><p id="create-status" role="status" aria-live="polite"></p>
<p class="status-footer">创建后将进入演示收银台，无需提供真实支付信息。</p></section>
<section id="checkout" aria-labelledby="page-title" aria-busy="true" data-tone="neutral" hidden>
<p class="eyebrow">Demo checkout</p><h2 id="page-title">正在读取演示订单</h2><p id="amount" aria-live="polite"></p>
<fieldset id="methods" disabled><legend id="method-legend">选择模拟支付方式</legend></fieldset>
<button id="continue" class="primary" type="button" disabled>确认模拟支付（不扣款）</button>
<div class="state-copy"><p id="status" role="status" aria-live="polite">正在读取服务器演示状态…</p><p id="result-description" class="muted">结果验证完成后将在这里显示。</p></div>
<p id="error" role="alert" hidden></p><button id="retry-status" class="secondary primary" type="button" hidden>重新查询结果</button>
<a class="link-button" href="/">创建新的演示订单</a></section>
</div><aside class="panel summary" aria-labelledby="order-summary-title"><p class="eyebrow">Order summary</p><h2 id="order-summary-title">演示订单摘要</h2>
<div class="item"><span class="item-mark" aria-hidden="true">e</span><div><p>模拟体验项目</p><small id="order-session">临时演示订单 · 1 项</small></div></div>
<dl><div><dt>模拟方式</dt><dd id="summary-method">微信支付（模拟）</dd></div><div><dt>演示金额</dt><dd id="summary-original-amount">￥10.00</dd></div><div><dt>真实扣款</dt><dd>无</dd></div><div class="total"><dt>模拟合计</dt><dd id="summary-amount">￥10.00</dd></div></dl>
<p class="summary-note">金额固定，所有结果均为演示。请勿用于真实交易。</p>
<details><summary>演示使用说明</summary><p>选择场景后创建新订单。待确认结果不会视为成功，您可以重新查询状态。</p><p>免费服务可能休眠，首次打开请稍候。订单保存在内存中，休眠或重启后清空。</p></details></aside></main>
<footer><p>ElmPay 演示环境 · 不发生真实扣款</p><p>临时演示状态保存在内存中，服务休眠或重启后清空。</p></footer></div></body></html>`,
  };
}
