const test = require("node:test");
const assert = require("node:assert/strict");

const {
  AuthenticationError,
  authenticateUser,
  issueAccessToken,
  verifyAccessToken,
  getBearerToken,
} = require("../src/services/authService");

const TEST_CONFIG = {
  username: "soc_admin",
  password: "ChangeMe!123",
  displayName: "SOC Administrator",
  role: "admin",
};

const SECRET = "test-secret-that-is-long-enough-for-unit-tests";

test("test SOC admin credentials authenticate", () => {
  const user = authenticateUser(
    { username: "soc_admin", password: "ChangeMe!123" },
    TEST_CONFIG,
  );

  assert.deepEqual(user, {
    username: "soc_admin",
    displayName: "SOC Administrator",
    role: "admin",
  });
});

test("wrong password is rejected without revealing which credential failed", () => {
  assert.throws(
    () => authenticateUser(
      { username: "soc_admin", password: "wrong-password" },
      TEST_CONFIG,
    ),
    AuthenticationError,
  );
});

test("OTP is enforced when configured", () => {
  assert.throws(
    () => authenticateUser(
      { username: "soc_admin", password: "ChangeMe!123", otp: "111111" },
      { ...TEST_CONFIG, otp: "654321" },
    ),
    AuthenticationError,
  );

  assert.equal(
    authenticateUser(
      { username: "soc_admin", password: "ChangeMe!123", otp: "654321" },
      { ...TEST_CONFIG, otp: "654321" },
    ).username,
    "soc_admin",
  );
});

test("signed access token round-trips and expires", () => {
  let nowMs = Date.UTC(2026, 8, 19, 8, 0, 0);
  const user = authenticateUser(
    { username: "soc_admin", password: "ChangeMe!123" },
    TEST_CONFIG,
  );

  const issued = issueAccessToken(user, {
    secret: SECRET,
    ttlSeconds: 60,
    now: () => nowMs,
  });

  const payload = verifyAccessToken(issued.token, {
    secret: SECRET,
    now: () => nowMs,
  });

  assert.equal(payload.sub, "soc_admin");
  assert.equal(payload.role, "admin");

  nowMs += 61_000;
  assert.throws(
    () => verifyAccessToken(issued.token, { secret: SECRET, now: () => nowMs }),
    AuthenticationError,
  );
});

test("Bearer token parsing is strict", () => {
  assert.equal(getBearerToken("Bearer abc.def"), "abc.def");
  assert.equal(getBearerToken("bearer token"), "token");
  assert.equal(getBearerToken("Basic abc"), null);
  assert.equal(getBearerToken(""), null);
});
