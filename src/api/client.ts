const csrfToken = () => {
  if (typeof document === "undefined") return "";
  return document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("sentinel_csrf="))
    ?.split("=")
    .slice(1)
    .join("=") || "";
};

const csrfMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export const api = async <T,>(path: string, options: RequestInit = {}, token?: string): Promise<T> => {
  const method = String(options.method || "GET").toUpperCase();
  const csrf = csrfToken();
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(csrf && csrfMethods.has(method) ? { "X-CSRF-Token": csrf } : {}),
      ...(options.headers || {})
    }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
};
