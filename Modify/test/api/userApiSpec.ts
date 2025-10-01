"// Helper to obtain test credentials from environment (avoid hard-coded secrets in tests)
function getTestCreds() {
  const email = process.env.TEST_USER_EMAIL?.trim();
  const password = process.env.TEST_USER_PASSWORD?.trim();
  if (!email || !password) {
    throw new Error(
      'Missing TEST_USER_EMAIL/TEST_USER_PASSWORD environment variables required for tests. ' +
      'Set them or provide TEST_AUTH_TOKEN to skip login step.'
    );
  }
  return { email, password };
}

/**
 * getAuthHeader()
 * - Primary: if TEST_AUTH_TOKEN is set, use it (suitable for CI secrets/secret manager).
 * - Fallback: perform a login to obtain a fresh token using TEST_USER_EMAIL / TEST_USER_PASSWORD.
 * Returns a Promise that resolves to an object suitable to pass as frisby headers `{ Authorization: 'Bearer ...' }`.
 */
function getAuthHeader() {
  const envToken = process.env.TEST_AUTH_TOKEN?.trim();
  if (envToken) {
    return Promise.resolve({ Authorization: `Bearer ${envToken}` });
  }

  // fallback: perform a login request to obtain token dynamically
  const { email, password } = getTestCreds();
  return frisby
    .post(`${REST_URL}/user/login`, {
      headers: { 'Content-Type': 'application/json' },
      body: { email, password }
    })
    .expect('status', 200)
    .then((res) => {
      // Support both common shapes: res.body.authentication.token or res.body.token
      const token =
        (res?.json?.authentication?.token) ??
        (res?.json?.token) ??
        (res?.body && (res.body.authentication?.token || res.body.token));
      if (!token) {
        throw new Error('Login succeeded but no token was returned by /user/login');
      }
      return { Authorization: `Bearer ${token}` };
    });
}

// ===== Replaced hard-coded Authorization header usages =====

// Previously:
// return frisby.get(`${REST_URL}/user/whoami`, { headers: { Authorization: 'BoarBeatsBear' } }).expect('status', 200)

// Now:
return getAuthHeader().then((headers) =>
  frisby.get(`${REST_URL}/user/whoami`, { headers }).expect('status', 200)
);

// Previously (long hard-coded JWT):
// return frisby.get(`${REST_URL}/user/whoami`, { headers: { Authorization: '<long-jwt>' } })

// Now use the same helper so tests remain consistent:
return getAuthHeader().then((headers) =>
  frisby.get(`${REST_URL}/user/whoami`, { headers }).expect('status', 200)
);
"