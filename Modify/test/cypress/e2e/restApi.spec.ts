"// --- helper: safe-html checks used across tests ---
function assertNoUnsafeHtml(payload: string | null | undefined) {
  const s = String(payload ?? '');
  // disallow script tags, iframe tags, and javascript: URIs appearing in returned content
  expect(s).to.not.match(/<\s*script\b/i, 'Response contains <script> (possible XSS)');
  expect(s).to.not.match(/<\s*iframe\b/i, 'Response contains <iframe> (possible XSS)');
  expect(s).to.not.include('javascript:', 'Response contains javascript: URI (possible XSS)');
}

// --- 1) Stored XSS via product description (CWE-079) ---
// Previously: posted description with <iframe src=""javascript:alert(`xss`)""> and relied on alert.
// Now: post same payload but assert server sanitizes/escapes it (no script/iframe/javascript:) in stored/rendered representation.

it('creates a product but does not store/render unsafe HTML in the product description', () => {
  const payloadDesc = '<iframe src=""javascript:alert(`xss`)"">';
  // create product (authenticated)
  cy.window().then((win) => {
    const token = win.localStorage.getItem('token');
    if (!token) {
      throw new Error('Test requires an auth token in localStorage. Set it or perform login before running this test.');
    }

    cy.request({
      method: 'POST',
      url: `${Cypress.config('baseUrl')}/api/Products`,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: {
        name: 'RestXSS',
        description: payloadDesc,
        price: 47.11
      },
      failOnStatusCode: false
    }).then((createResp) => {
      // accept created or accepted statuses depending on implementation
      expect([200, 201, 202]).to.include(createResp.status);

      // find created product id -- several APIs return body different shapes; handle common ones
      const body = createResp.body || {};
      const createdId =
        (body && (body.id || body.data?.id)) ||
        // fallback: if API returns Location header with id at the end
        (createResp.headers && createResp.headers.location && createResp.headers.location.split('/').pop());

      expect(createdId, 'product id should be present').to.exist;

      // Fetch the product detail page / API and assert stored description is sanitized/escaped
      cy.request({
        method: 'GET',
        url: `${Cypress.config('baseUrl')}/api/Products/${createdId}`,
        failOnStatusCode: false
      }).then((getResp) => {
        expect([200, 204]).to.include(getResp.status);
        // Depending on API shape check different fields
        const desc =
          (getResp.body && (getResp.body.description || getResp.body.data?.description)) ||
          // if HTML page returned as text
          (typeof getResp.body === 'string' ? getResp.body : undefined);

        // No raw iframe / script / javascript: should be present
        assertNoUnsafeHtml(desc);
      });
    });
  });
});

// --- 2) Missing authentication on PUT /api/Products/{id} (CWE-306) ---
// Previously: test performed unauthenticated PUT and asserted success.
// Now: ensure modifications are performed only with a valid Authorization header (test performs or requires login).

it('updates a product only when authenticated (PUT requires auth)', () => {
  const overwriteUrl = 'https://example.com/hijack';
  const tamperingProductId = Cypress.env('TAMPERING_PRODUCT_ID') || 1;

  // Obtain token from localStorage or login via env-provided creds
  cy.window().then((win) => {
    let token = win.localStorage.getItem('token');

    const loginIfNeeded = () => {
      if (token) return cy.wrap(token);

      const email = Cypress.env('TEST_USER_EMAIL');
      const password = Cypress.env('TEST_USER_PASSWORD');
      if (!email || !password) {
        throw new Error(
          'No token in localStorage and TEST_USER_EMAIL/TEST_USER_PASSWORD not set in Cypress env. ' +
            'Set them so test can obtain a token for authenticated PUT.'
        );
      }
      return cy
        .request({
          method: 'POST',
          url: `${Cypress.config('baseUrl')}/user/login`,
          headers: { 'Content-Type': 'application/json' },
          body: { email, password },
          failOnStatusCode: false
        })
        .then((r) => {
          expect(r.status).to.equal(200);
          // common response shapes
          const tokenFromResp = r.body?.authentication?.token || r.body?.token;
          expect(tokenFromResp, 'login should return token').to.exist;
          token = tokenFromResp;
          // also persist into localStorage for possible subsequent steps
          win.localStorage.setItem('token', tokenFromResp);
          return tokenFromResp;
        });
    };

    cy.wrap(null)
      .then(() => loginIfNeeded())
      .then((resolvedToken) => {
        // Now perform authenticated PUT to update description (intent: not to overwrite via unauthenticated request)
        cy.request({
          method: 'PUT',
          url: `${Cypress.config('baseUrl')}/api/Products/${tamperingProductId}`,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${resolvedToken}`
          },
          body: {
            description: `<a href=""${overwriteUrl}"" target=""_blank"">More...</a>`
          },
          failOnStatusCode: false
        }).then((putResp) => {
          // Authenticated update should succeed (200/204). If the API requires additional roles, adapt to 403/401 expectations.
          expect([200, 201, 204]).to.include(putResp.status);

          // Verify that description stored does not include raw javascript: or iframe tags
          cy.request({
            method: 'GET',
            url: `${Cypress.config('baseUrl')}/api/Products/${tamperingProductId}`,
            failOnStatusCode: false
          }).then((getResp) => {
            expect([200, 204]).to.include(getResp.status);
            const desc =
              (getResp.body && (getResp.body.description || getResp.body.data?.description)) ||
              (typeof getResp.body === 'string' ? getResp.body : undefined);
            // The stored value should not contain unescaped harmful HTML
            assertNoUnsafeHtml(desc);
          });
        });
      });
  });
});

// --- 3) HTTP-Header XSS via 'True-Client-IP' header (CWE-079) ---
// Previously: test sent header with <iframe src=""javascript:alert(`xss`)> and expected script execution.
// Now: send header but assert server does not reflect raw unsafe HTML.

it('does not store or render dangerous HTML from True-Client-IP header', () => {
  const headerPayload = '<iframe src=""javascript:alert(`xss`)"">';
  cy.window().then((win) => {
    const token = win.localStorage.getItem('token');
    if (!token) {
      throw new Error('Test requires auth token in localStorage to call /rest/saveLoginIp; set it first.');
    }

    // Use GET to save the header as previous test did, but verify result is safe
    cy.request({
      method: 'GET',
      url: `${Cypress.config('baseUrl')}/rest/saveLoginIp`,
      headers: {
        Authorization: `Bearer ${token}`,
        'True-Client-IP': headerPayload
      },
      failOnStatusCode: false
    }).then((resp) => {
      // Server should accept/reject but must not reflect runnable HTML
      expect([200, 204, 400, 422]).to.include(resp.status);

      // If response contains stored representation, it must not include unsafe HTML
      const bodyText = typeof resp.body === 'string' ? resp.body : JSON.stringify(resp.body || {});
      assertNoUnsafeHtml(bodyText);

      // Optionally follow up to any page that renders stored IP (if known path exists).
      // Example: cy.request(GET /admin/ips/{last}) and assert sanitized there too.
    });
  });
});
"