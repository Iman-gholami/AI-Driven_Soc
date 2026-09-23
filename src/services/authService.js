const crypto = require("node:crypto");

class AuthenticationError extends Error {
  constructor(message = "Invalid credentials") {
    super(message);
    this.name = "AuthenticationError";
  }
}

function authenticateUser(input = {}, config = {}) {
  const username = String(input.username || "").trim();
  const password = String(input.password || "");
  const otp = String(input.otp || "").trim();

  const expectedUsername = String(config.username || "").trim();
  const expectedPassword = String(config.password || "");
  const expectedOtp = String(config.otp || "").trim();

  if (!expectedUsername || !expectedPassword) {
    throw new AuthenticationError("Authentication is not configured");
  }

  if (!secureEqual(username, expectedUsername) || !secureEqual(password, expectedPassword)) {
    throw new AuthenticationError();
  }

  if (expectedOtp && !secureEqual(otp, expectedOtp)) {
    throw new AuthenticationError();
  }

  return {
    username: expectedUsername,
    displayName: String(config.displayName || expectedUsername),
    role: String(config.role || "analyst"),
  };
}

function issueAccessToken(user, { secret, ttlSeconds = 8 * 60 * 60, now = Date.now } = {}) {
  if (!secret) throw new Error("AUTH_TOKEN_SECRET is required");

  const issuedAt = Math.floor(now() / 1000);
  const expiresAt = issuedAt + Math.max(Number(ttlSeconds) || 0, 60);
  const payload = {
    sub: String(user.username),
    name: String(user.displayName || user.username),
    role: String(user.role || "analyst"),
    iat: issuedAt,
    exp: expiresAt,
    jti: crypto.randomBytes(12).toString("hex"),
  };

  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = sign(encodedPayload, secret);

  return {
    token: `${encodedPayload}.${signature}`,
    expiresAt: new Date(expiresAt * 1000).toISOString(),
    payload,
  };
}

function verifyAccessToken(token, { secret, now = Date.now } = {}) {
  if (!secret) throw new AuthenticationError("Authentication is not configured");
  const value = String(token || "").trim();
  const parts = value.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) throw new AuthenticationError("Invalid access token");

  const [encodedPayload, providedSignature] = parts;
  const expectedSignature = sign(encodedPayload, secret);
  if (!secureEqual(providedSignature, expectedSignature)) throw new AuthenticationError("Invalid access token");

  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(encodedPayload));
  } catch (_) {
    throw new AuthenticationError("Invalid access token");
  }

  const currentTime = Math.floor(now() / 1000);
  if (!payload?.sub || !Number.isFinite(payload?.exp) || payload.exp <= currentTime) {
    throw new AuthenticationError("Access token expired");
  }

  return payload;
}

function getBearerToken(headerValue) {
  const match = String(headerValue || "").match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function secureEqual(left, right) {
  const leftDigest = crypto.createHash("sha256").update(String(left)).digest();
  const rightDigest = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function sign(value, secret) {
  return crypto.createHmac("sha256", String(secret)).update(value).digest("base64url");
}

function base64UrlEncode(value) {
  return Buffer.from(String(value), "utf8").toString("base64url");
}

function base64UrlDecode(value) {
  return Buffer.from(String(value), "base64url").toString("utf8");
}

module.exports = {
  AuthenticationError,
  authenticateUser,
  issueAccessToken,
  verifyAccessToken,
  getBearerToken,
  secureEqual,
};
