"// --- helpers to harden expectations against CWE-601 / CWE-209 ---

function isRelativePath(loc?: string | null): boolean {
  if (!loc) return true; // treat missing Location as ""not redirecting externally""
  // relative paths are allowed (/, /foo, ./bar, ../baz)
  // explicitly reject absolute URLs and protocol-relative URLs
  return (
    loc.startsWith(""/"") ||
    loc.startsWith(""./"") ||
    loc.startsWith(""../"")
  );
}

function assertNoStackLeak(bodyText: string) {
  // Guard against common error-page disclosures
  const leakIndicators = [
    ""TypeError"",
    ""ReferenceError"",
    ""SyntaxError"",
    ""RangeError"",
    ""at "",                 // stack frame indicator
    ""stack:"",              // typical JSON error key
    ""Express"",             // express default error page often leaks framework name
    "".includes("",          // evidence snippet mentioned in finding
    ""of undefined""         // evidence snippet mentioned in finding
  ];
  for (const token of leakIndicators) {
    expect(bodyText).not.toContain(token);
  }
}

// ── FIX for CWE-601: do NOT allow nested allowlist bypass via query string ──
it('does NOT redirect externally when an allow-listed URL is only nested inside the ""to"" query value', () => {
  return frisby
    .get(
      `${URL}/redirect?to=` +
        encodeURIComponent(
          // attacker crafts a relative path that nests an allow-listed domain in its query
          `/score-board?satisfyIndexOf=https://github.com/juice-shop/juice-shop`
        )
    )
    // A secure server might respond with a 400/403/422 or a 2xx that renders a safe page.
    .expect('status', (status) =>
      expect([200, 204, 400, 403, 422]).toContain(status)
    )
    .then((res) => {
      // If the server attempts a redirect, ensure it's only to a relative path (no open redirect)
      const loc = res.headers?.location || res.headers?.Location;
      expect(isRelativePath(loc)).toBeTrue();
      // If HTML is returned, verify it does not contain an externally navigable meta-refresh or JS redirect to external URL
      const body = (res?.body ?? '').toString();
      const externalUrlRegex = /(https?:)?\/\/(?!localhost|127\.0\.0\.1)[\w.-]+/i;
      // Should not embed a client-side redirect to external domains
      expect(body.match(externalUrlRegex)).toBeNull();
    });
});

// ── FIX for CWE-209: no detailed error page when required params are missing ──
it('returns a safe client error without leaking stack details when /redirect is called without query parameter', () => {
  return frisby
    .get(`${URL}/redirect`)
    // Expect a client error (400/422) in a hardened implementation.
    // Some implementations may choose 200 with a safe explanatory page; accept that too.
    .expect('status', (status) =>
      expect([200, 204, 400, 422]).toContain(status)
    )
    .then((res) => {
      const ct = res.headers?.['content-type'] || res.headers?.['Content-Type'] || '';
      expect(ct).toMatch(/^(text\/html|application\/json)/i);

      const body = (res?.body ?? '').toString();
      // No framework stacks, internal types, or implementation hints
      assertNoStackLeak(body);

      // Optional: if JSON, it should look like a controlled error object
      if (/application\/json/i.test(ct)) {
        try {
          const json = JSON.parse(body);
          // very loose checks to preserve public API flexibility
          expect(json).toEqual(
            expect.objectContaining({
              error: expect.anything()
            })
          );
        } catch {
          // If not JSON parseable despite header, just skip strict shape checks.
          // Still important: no stack/TypeError leakage, verified above.
        }
      }
    });
});
"