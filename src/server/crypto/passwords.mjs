import crypto from "node:crypto";

export const hashPassword = (password, salt = crypto.randomBytes(16).toString("hex")) => {
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 32, "sha512").toString("hex");
  return { salt, hash };
};

export const verifyPassword = (password, stored) => hashPassword(password || "", stored.salt).hash === stored.hash;

export const generateCredential = () => `${crypto.randomBytes(18).toString("base64url")}!A7`;
