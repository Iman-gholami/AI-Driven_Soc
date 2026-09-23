const { settings } = require("../core/config");
const {
  AuthenticationError,
  getBearerToken,
  verifyAccessToken,
} = require("../services/authService");

function requireAuth(req, res, next) {
  if (!settings.authEnabled) return next();

  try {
    const token = getBearerToken(req.headers.authorization);
    if (!token) {
      return res.status(401).json({ detail: "Authentication required" });
    }

    const payload = verifyAccessToken(token, {
      secret: settings.authTokenSecret,
    });

    req.user = {
      username: payload.sub,
      displayName: payload.name || payload.sub,
      role: payload.role || "analyst",
    };
    return next();
  } catch (error) {
    if (error instanceof AuthenticationError) {
      return res.status(401).json({ detail: error.message });
    }
    req.log?.error({ err: error }, "auth_middleware_failed");
    return res.status(500).json({ detail: "Authentication failure" });
  }
}

module.exports = { requireAuth };
