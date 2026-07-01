import { logger } from "../logging/logger.mjs";

export const errorHandler = (err, _req, res, _next) => {
  const status = err.status || 500;
  if (status === 500) {
    logger.error("request.unhandled_error", { err });
  }
  res.status(status).json({ error: status === 500 ? "Internal server error" : err.message });
};
