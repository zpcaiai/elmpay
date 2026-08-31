const ALLOWED_EVENTS = new Set([
  "ADMIN_STARTED", "ADMIN_STOPPED", "REQUEST_REJECTED", "DEPENDENCY_DEGRADED", "SERVER_ERROR",
]);
const ALLOWED_FIELDS = new Set(["event", "code", "method", "route", "requestId", "status"]);
const SAFE_VALUE = /^[A-Za-z0-9._:/-]{1,128}$/;

export class SafeLogger {
  constructor(sink = process.stdout) { this.sink = sink; }

  event(event, fields = {}) {
    if (!ALLOWED_EVENTS.has(event)) throw new TypeError("unsupported log event");
    const output = { event };
    for (const [key, value] of Object.entries(fields)) {
      if (ALLOWED_FIELDS.has(key) && typeof value === "string" && SAFE_VALUE.test(value)) output[key] = value;
      else if (ALLOWED_FIELDS.has(key) && Number.isInteger(value)) output[key] = value;
    }
    this.sink.write(`${JSON.stringify(output)}\n`);
  }
}
