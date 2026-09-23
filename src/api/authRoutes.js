const express = require("express");
const rateLimit = require("express-rate-limit");
const { settings } = require("../core/config");
const { successResponse, errorResponse } = require("../utils/response");
const { requireAuth } = require("./middleware/requireAuth");
const {
  AuthenticationError,
  authenticateUser,
  issueAccessToken,
} = require("../services/authService");

function createAuthRouter() {
  const router = express.Router();

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: { success: false, detail: "Too many sign-in attempts. Try again later." },
  });

  router.post("/login", loginLimiter, (req, res) => {
    try {
      if (!settings.authEnabled) {
        return errorResponse(res, "Panel authentication is disabled", 503);
      }
      if (!settings.authTokenSecret) {
        return errorResponse(res, "Panel authentication is not configured", 503);
      }

      const user = authenticateUser(req.body || {}, {
        username: settings.authUsername,
        password: settings.authPassword,
        otp: settings.authOtp,
        displayName: settings.authDisplayName,
        role: settings.authRole,
      });

      const remember = req.body?.remember === true;
      const ttlSeconds = remember
        ? settings.authRememberTokenTtlSeconds
        : settings.authTokenTtlSeconds;
      const issued = issueAccessToken(user, {
        secret: settings.authTokenSecret,
        ttlSeconds,
      });

      req.log?.info({ username: user.username, role: user.role, remember }, "panel_login_succeeded");
      return successResponse(res, {
        token: issued.token,
        expiresAt: issued.expiresAt,
        user,
      });
    } catch (error) {
      if (error instanceof AuthenticationError) {
        req.log?.warn(
          { username: String(req.body?.username || "").slice(0, 80) },
          "panel_login_failed",
        );
        const status = /not configured/i.test(error.message) ? 503 : 401;
        return errorResponse(res, status === 401 ? "Invalid username, password, or one-time code" : error.message, status);
      }
      req.log?.error({ err: error }, "panel_login_error");
      return errorResponse(res, "Unable to sign in", 500);
    }
  });

  router.get("/me", requireAuth, (req, res) => successResponse(res, { user: req.user }));

  router.post("/logout", requireAuth, (req, res) => {
    req.log?.info({ username: req.user?.username }, "panel_logout");
    return successResponse(res, { loggedOut: true });
  });

  return router;
}

module.exports = { createAuthRouter };
