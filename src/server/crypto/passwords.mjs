import crypto from "node:crypto";

export const hashPassword = (password, salt = crypto.randomBytes(16).toString("hex")) => {
  const hash = crypto.pbkdf2Sync(password, salt, 210000, 32, "sha512").toString("hex");
  return { salt, hash };
};

export const verifyPassword = (password, stored) => {
  if (!stored?.salt || !stored?.hash || typeof stored.hash !== "string") return false;
  const expected = hashPassword(password || "", stored.salt).hash;
  const expectedBuffer = Buffer.from(expected, "hex");
  const storedBuffer = Buffer.from(stored.hash, "hex");
  return expectedBuffer.length === storedBuffer.length && crypto.timingSafeEqual(expectedBuffer, storedBuffer);
};

export const generateCredential = () => `${crypto.randomBytes(18).toString("base64url")}!A7`;
