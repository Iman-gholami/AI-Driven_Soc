const { settings } = require("../../core/config");
const {
  AuthenticationError,
  getBearerToken,
  verifyAccessToken,
} = require("../../services/authService");
const { errorResponse } = require("../../utils/response");

function requireAuth(req, res, next) {
  if (!settings.authEnabled) return next();

  try {
    const token = getBearerToken(req.headers.authorization);
    if (!token) {
      return errorResponse(res, "Authentication required", 401);
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
      return errorResponse(res, error.message, 401);
    }
    req.log?.error({ err: error }, "auth_middleware_failed");
    return errorResponse(res, "Authentication failure", 500);
  }
}

module.exports = { requireAuth };
