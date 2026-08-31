import { createServer } from "node:https";
import { readFileSync } from "node:fs";
import { loadProductionConfig } from "./config.mjs";
import { AuthorizationPolicy } from "./authorization-policy.mjs";
import { FileRevocationSource, loadCorporateJwks, OperatorTokenVerifier } from "./operator-auth.mjs";
import { PostgresAdminStore, PsqlRunner } from "./postgres-store.mjs";
import { StrictAdminUpstream } from "./upstream-client.mjs";
import { SafeLogger } from "./safe-logger.mjs";
import { createAdminHandler } from "./server.mjs";
import { AdminActionDispatcher } from "./action-dispatcher.mjs";

async function bootstrap() {
  const config = loadProductionConfig();
  const logger = new SafeLogger();
  const keys = loadCorporateJwks(config.jwksPath);
  const store = new PostgresAdminStore(new PsqlRunner({
    psqlPath: config.psqlPath, service: config.pgService, serviceFile: config.pgServiceFile,
    rootCertificate: config.pgRootCertificate, timeoutMs: config.databaseTimeoutMs,
  }));
  // No listener or dispatcher is created until the fixed login, FORCE-RLS policies and
  // exact table/sequence/routine ACL manifest have been proven against the live database.
  await store.verifyRuntimeContract();
  const revocationSource = new FileRevocationSource({
    path: config.revocationPath, keys, issuer: config.issuer, maximumAgeSeconds: 60,
  });
  // Verify the mounted revocation control before accepting any socket.
  revocationSource.current(new Date());
  const authenticator = new OperatorTokenVerifier({
    issuer: config.issuer, audience: config.audience, keys, revocationSource, replayStore: store,
    clockSkewSeconds: 60, maximumTokenSeconds: 3600, stepUpSeconds: 300,
  });
  const policy = AuthorizationPolicy.load({
    authorizationPath: config.authorizationPath, actionPolicyPath: config.actionPolicyPath,
  });
  const upstream = new StrictAdminUpstream({
    baseUrl: config.upstreamBaseUrl, caPath: config.upstreamCaPath,
    certificatePath: config.upstreamCertificatePath, privateKeyPath: config.upstreamPrivateKeyPath,
    timeoutMs: config.upstreamTimeoutMs,
  });
  const dispatcher = new AdminActionDispatcher({ store, upstream, logger });
  const handler = createAdminHandler({ authenticator, policy, store, upstream,
    publicOrigin: config.publicOrigin, logger, dispatcher });
  const server = createServer({
    cert: readFileSync(config.tlsCertificatePath), key: readFileSync(config.tlsPrivateKeyPath),
    minVersion: "TLSv1.3", maxVersion: "TLSv1.3", maxHeaderSize: 16_384,
    requestTimeout: 10_000, headersTimeout: 5_000, keepAliveTimeout: 5_000,
  }, handler);
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });
  server.on("error", () => {
    logger.event("SERVER_ERROR", { code: "HTTPS_SERVER_ERROR" });
    process.exitCode = 1;
    void dispatcher.stop();
  });
  dispatcher.start();
  server.listen(config.port, config.host, () => logger.event("ADMIN_STARTED",
    { status: 200, route: "https-listener" }));
  let shuttingDown = false;
  const shutdown = async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    server.close();
    await dispatcher.stop();
    logger.event("ADMIN_STOPPED", { status: 200 });
    process.exitCode = 0;
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
  return server;
}

try { await bootstrap(); }
catch {
  new SafeLogger(process.stderr).event("SERVER_ERROR", { code: "STARTUP_CONFIGURATION_INVALID" });
  process.exitCode = 1;
}
