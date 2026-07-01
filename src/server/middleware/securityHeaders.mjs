const unique = (values) => [...new Set(values.filter(Boolean))];

export const buildContentSecurityPolicy = (appConfig) => {
  const connectSources = appConfig.isProduction
    ? ["'self'"]
    : [
        "'self'",
        `http://${appConfig.host}:${appConfig.port}`,
        `ws://${appConfig.host}:${appConfig.port}`,
        `http://localhost:${appConfig.port}`,
        `ws://localhost:${appConfig.port}`
      ];

  const directives = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    `connect-src ${unique(connectSources).join(" ")}`,
    "font-src 'self' data:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ];

  if (appConfig.isProduction) {
    directives.push("upgrade-insecure-requests");
  }

  return directives.join("; ");
};

export const buildSecurityHeaders = (appConfig) => {
  const headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-DNS-Prefetch-Control": "off",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Origin-Agent-Cluster": "?1",
    "Content-Security-Policy": buildContentSecurityPolicy(appConfig)
  };

  if (appConfig.isProduction) {
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  }

  return headers;
};

export const securityHeaders = (appConfig) => (_req, res, next) => {
  for (const [name, value] of Object.entries(buildSecurityHeaders(appConfig))) {
    res.setHeader(name, value);
  }
  next();
};
