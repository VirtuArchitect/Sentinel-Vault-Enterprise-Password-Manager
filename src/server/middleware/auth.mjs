import { resolveSessionContext } from "../services/sessionService.mjs";

export const parseCookies = (header = "") => Object.fromEntries(String(header || "")
  .split(";")
  .map((part) => part.trim())
  .filter(Boolean)
  .map((part) => {
    const separator = part.indexOf("=");
    if (separator === -1) return [part, ""];
    return [
      decodeURIComponent(part.slice(0, separator)),
      decodeURIComponent(part.slice(separator + 1))
    ];
  }));

const unsafeMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const bearerToken = (req) => {
  const authorization = req.headers.authorization || "";
  return authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : "";
};

const cookieToken = (req) => parseCookies(req.headers.cookie).sentinel_session || "";

export const auth = (req, res, next) => {
  const token = bearerToken(req) || cookieToken(req);
  const context = resolveSessionContext(token);
  if (!context) return res.status(401).json({ error: "Authentication required" });
  if (!bearerToken(req) && unsafeMethods.has(req.method)) {
    const presented = String(req.get("x-csrf-token") || "");
    if (!context.session.csrfToken || presented !== context.session.csrfToken) {
      return res.status(403).json({ error: "CSRF token required" });
    }
  }
  req.user = context.user;
  req.authToken = token;
  req.csrfToken = context.session.csrfToken;
  next();
};
