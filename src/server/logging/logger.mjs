const sensitiveKey = /password|passphrase|secret|token|authorization|cookie|credential|private.?key|client.?secret|signature/i;
const bearerToken = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const sentinelToken = /\b(sentinel[_-]?(?:service[_-]?)?token=)[^&\s]+/gi;
const redacted = "[REDACTED]";

export const redactForLog = (value, seen = new WeakSet()) => {
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactForLog(value.message, seen),
      stack: redactForLog(value.stack?.split("\n").slice(0, 6).join("\n"), seen)
    };
  }
  if (typeof value === "string") {
    return value
      .replace(bearerToken, "Bearer [REDACTED]")
      .replace(sentinelToken, `$1${redacted}`);
  }
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (Array.isArray(value)) return value.map((item) => redactForLog(item, seen));

  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    sensitiveKey.test(key) ? redacted : redactForLog(item, seen)
  ]));
};

const writeLog = (level, event, context = {}) => {
  const payload = {
    ts: new Date().toISOString(),
    level,
    service: "sentinel-vault",
    event,
    ...redactForLog(context)
  };
  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
};

export const logger = {
  info: (event, context) => writeLog("info", event, context),
  warn: (event, context) => writeLog("warn", event, context),
  error: (event, context) => writeLog("error", event, context)
};
