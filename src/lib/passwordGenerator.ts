import type { PasswordGeneratorOptions } from "../types";

export const generatePassword = (options: PasswordGeneratorOptions) => {
  const pools = [
    options.upper ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "",
    options.lower ? "abcdefghijkmnopqrstuvwxyz" : "",
    options.digits ? "23456789" : "",
    options.symbols ? "!#$%&*+-=?@^_" : ""
  ].filter(Boolean);
  const joined = pools.join("") || "abcdefghijkmnopqrstuvwxyz23456789";
  const chars = Array.from({ length: options.length }, (_, index) => {
    const pool = pools[index % pools.length] || joined;
    return pool[Math.floor(Math.random() * pool.length)];
  });
  return chars.sort(() => Math.random() - 0.5).join("");
};
