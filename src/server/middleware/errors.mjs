export const errorHandler = (err, _req, res, _next) => {
  const status = err.status || 500;
  res.status(status).json({ error: status === 500 ? "Internal server error" : err.message });
};
