import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { BrowserSecurityRuntime } from '../../checkout-web/src/browser-security.mjs';
import { demoHeaders } from './bridge.mjs';

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
:root{font-family:system-ui,sans-serif;color:#172926;background:#f0f5f2}body{margin:0;padding:36px 20px}
main{max-width:760px;margin:auto;background:#fff;border:1px solid #d5e2db;border-radius:20px;padding:32px}
aside{background:#fff4cf;border:1px solid #e5ca65;border-radius:12px;padding:16px;line-height:1.6}
h1{font-size:32px;margin:24px 0 8px}p{line-height:1.7}label,select,button{font:inherit}
select,button{padding:12px;border-radius:8px;border:1px solid #8aa79a}button{background:#17644b;color:white;cursor:pointer}
button:disabled{opacity:.5;cursor:default}section{margin-top:28px}fieldset{border:1px solid #d5e2db;padding:16px;margin:16px 0}
fieldset label{display:block;padding:10px}a{color:#17644b}footer{font-size:13px;color:#52685d;margin-top:28px}
[hidden]{display:none!important}#error{color:#b32323}#status{font-weight:600}
</style><script type="module" src="/demo.mjs" nonce="${nonce}" integrity="${sri}" crossorigin="anonymous"></script>
</head><body><main>
<aside role="note"><strong>免费演示 · 真实支付已禁用</strong><br>
所有金额和支付结果均为模拟数据，不发生真实扣款。请勿输入真实卡号、密码、商户密钥或个人信息。</aside>
<h1>ElmPay</h1><p>体验创建订单、进入收银台和服务器确认模拟结果的完整流程。</p>
<section id="demo-start"><h2>创建演示订单</h2><p>固定演示金额：USD 10.00</p>
<label for="scenario">模拟结果</label> <select id="scenario">
<option value="succeeded">模拟成功</option><option value="declined">模拟拒绝</option>
<option value="unknown">模拟未知结果</option></select>
<p><button id="create-demo" type="button">创建演示订单</button></p><p id="create-status" role="status" aria-live="polite"></p></section>
<section id="checkout" aria-labelledby="page-title" aria-busy="true" hidden>
<h2 id="page-title">演示收银台</h2><p id="amount" aria-live="polite"></p>
<fieldset id="methods" disabled><legend id="method-legend">选择演示方式</legend></fieldset>
<button id="continue" type="button" disabled>确认模拟支付</button>
<p id="status" role="status" aria-live="polite">正在读取服务器演示状态…</p>
<p id="error" role="alert" hidden></p><p><a href="/">创建新的演示订单</a></p></section>
<footer>演示状态保存在内存中，服务休眠或重启后清空。此页面不代表生产部署、支付渠道认证或真实支付验收。</footer>
</main></body></html>`,
  };
}
