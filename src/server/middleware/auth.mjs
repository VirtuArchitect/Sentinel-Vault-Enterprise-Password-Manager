import { resolveSession } from "../services/sessionService.mjs";

export const auth = (req, res, next) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const user = resolveSession(token);
  if (!user) return res.status(401).json({ error: "Authentication required" });
  req.user = user;
  next();
};
