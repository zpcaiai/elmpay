import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDemoBridge, demoConfiguration, demoHeaders } from './bridge.mjs';
import { demoAsset, renderDemoPage } from './page.mjs';

export async function startDemo(environment = process.env) {
  const configuration = demoConfiguration(environment);
  const root = fileURLToPath(new URL('../../../', import.meta.url));
  const library = resolve(root, 'apps/edge-gateway/build/install/edge-gateway/lib');
  if (!existsSync(library) || !readdirSync(library).some(name => name.endsWith('.jar'))) {
    throw new Error('built demo gateway distribution is required');
  }
  const port = Number(environment.PORT ?? 10000);
  if (!Number.isInteger(port) || port < 1024 || port > 65535
      || [configuration.gatewayPort, configuration.healthPort].includes(port)) {
    throw new Error('invalid demo public port');
  }
  const java = environment.ELMPAY_DEMO_JAVA_PATH ?? '/opt/java/openjdk/bin/java';
  if (!java.startsWith('/') || !existsSync(java)) throw new Error('demo Java runtime is required');
  const child = spawn(java, ['-Xmx160m', '-XX:MaxMetaspaceSize=96m', '-XX:MaxDirectMemorySize=16m',
    '-XX:ReservedCodeCacheSize=32m', '-Xss256k', '-XX:ActiveProcessorCount=1', '-XX:+UseSerialGC',
    '-cp', `${library}/*`, 'com.elmpay.gateway.PaymentGatewayApplication'], {
    env: configuration.childEnvironment, stdio: ['ignore', 'inherit', 'inherit'],
  });
  let alive = true; let stopping = false;
  child.once('error', () => { alive = false; console.error('demo_gateway_start_failed'); });
  child.once('exit', () => { alive = false; if (!stopping) console.error('demo_gateway_unavailable'); });
  const handler = createDemoBridge(configuration, {
    gatewayAlive: () => alive,
    page(_request, response) {
      const page = renderDemoPage(); response.writeHead(200, page.headers).end(page.html);
    },
    asset(path, response) {
      const asset = demoAsset(path);
      if (!asset) return false;
      response.writeHead(200, { ...demoHeaders, 'content-type': asset.type }).end(asset.bytes);
      return true;
    },
  });
  const server = createServer(handler);
  server.requestTimeout = 10000; server.headersTimeout = 5000;
  server.maxHeadersCount = 40;
  async function stop() {
    if (stopping) return;
    stopping = true;
    server.close();
    if (alive) child.kill('SIGTERM');
  }
  server.once('error', () => { console.error('demo_listener_failed'); void stop(); process.exitCode = 1; });
  process.once('SIGTERM', () => { void stop(); });
  process.once('SIGINT', () => { void stop(); });
  server.listen(port, '0.0.0.0', () => console.log(JSON.stringify({
    service: 'elmpay-free-demo', real_payments: false, mode: 'local-sandbox',
    gateway_pid: child.pid, public_port: port,
  })));
  return { server, child, stop };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await startDemo(); }
  catch { console.error('demo_configuration_unavailable'); process.exitCode = 1; }
}
