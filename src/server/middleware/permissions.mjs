import { hasPermission } from "../rbac/roles.mjs";

export const can = (permission) => (req, res, next) => {
  if (!hasPermission(req.user.role, permission)) return res.status(403).json({ error: "Insufficient role clearance" });
  next();
};
