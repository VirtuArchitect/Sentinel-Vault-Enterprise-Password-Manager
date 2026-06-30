const buckets = new Map();

export const rateLimit = ({ windowMs = 60000, max = 20 } = {}) => (req, res, next) => {
  if (process.env.NODE_ENV === "test") return next();

  const now = Date.now();
  const key = `${req.ip}:${req.path}`;
  const bucket = buckets.get(key) || { count: 0, resetAt: now + windowMs };

  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + windowMs;
  }

  bucket.count += 1;
  buckets.set(key, bucket);

  res.setHeader("X-RateLimit-Limit", String(max));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - bucket.count)));
  res.setHeader("X-RateLimit-Reset", String(Math.ceil(bucket.resetAt / 1000)));

  if (bucket.count > max) {
    return res.status(429).json({ error: "Too many requests" });
  }

  next();
};
