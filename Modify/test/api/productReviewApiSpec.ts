"// ===== [PATCH 1/2] — Remove hard-coded credentials (CWE-798) =====

// Helper to read test credentials from environment (or secure secret manager if your test runner injects one)
function getTestCreds() {
  const email = process.env.TEST_USER_EMAIL?.trim();
  const password = process.env.TEST_USER_PASSWORD?.trim();
  if (!email || !password) {
    throw new Error(
      ""Missing TEST_USER_EMAIL/TEST_USER_PASSWORD. "" +
        ""Provide credentials via environment variables for test login.""
    );
  }
  return { email, password };
}

// ... inside your login flow in this spec file:
it(""logs in with test user"", async () => {
  const { email, password } = getTestCreds();
  const res = await request(app)
    .post(""/user/login"")
    .send({ email, password }); // << no hard-coded literals
  expect(res.status).toBe(200);
  // keep existing assertions...
});
// ===== [PATCH 2/2] — Remove NoSQL operator payload (CWE-943) and assert safe behavior =====

// Assume you already created a review earlier in the suite (or create one here) and obtained its numeric id:
async function createReviewAndGetId(authHeader: string): Promise<number> {
  const createRes = await request(app)
    .post(""/rest/products/reviews"")
    .set(""Authorization"", authHeader)
    .send({ productId: 1, message: ""initial review"" });

  expect(createRes.status).toBeLessThan(400);
  const createdId = Number(createRes.body?.data?.id ?? createRes.body?.id);
  if (!Number.isInteger(createdId)) {
    throw new Error(""Expected numeric review id but got: "" + String(createdId));
  }
  return createdId;
}

it(""updates a single review by numeric id (no operators allowed)"", async () => {
  // Acquire auth (reuse your existing login/token code)
  const { email, password } = getTestCreds();
  const login = await request(app).post(""/user/login"").send({ email, password });
  expect(login.status).toBe(200);
  const authHeader = `Bearer ${login.body?.authentication?.token ?? login.body?.token}`;

  const safeReviewId = await createReviewAndGetId(authHeader);

  // ✅ SAFE: send a plain integer id, not an object with operators
  const patchRes = await request(app)
    .patch(""/rest/products/reviews"")
    .set(""Authorization"", authHeader)
    .send({
      id: safeReviewId, // was: { $ne: -1 }  ← ❌ NoSQL injection vector
      message:
        ""trololololololololololololololololololololololololololol""
    });

  expect(patchRes.status).toBeLessThan(400);
  // keep your existing positive assertions about the single review being updated…
});

// (Optional but recommended) Negative test ensuring operator objects are rejected by server-side validation.
// This doesn’t change API shape; it only codifies secure behavior.
it(""rejects NoSQL operator objects in id"", async () => {
  const { email, password } = getTestCreds();
  const login = await request(app).post(""/user/login"").send({ email, password });
  expect(login.status).toBe(200);
  const authHeader = `Bearer ${login.body?.authentication?.token ?? login.body?.token}`;

  const bad = await request(app)
    .patch(""/rest/products/reviews"")
    .set(""Authorization"", authHeader)
    .send({
      // ❌ previously used in the test; now we assert it is rejected
      id: { $ne: -1 },
      message: ""operator payload""
    });

  // Expect your API to reject operator objects (400/422). Adjust status to your validator’s contract.
  expect([400, 422]).toContain(bad.status);
});
"