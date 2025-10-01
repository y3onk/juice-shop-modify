"// === Hardened tests for CWE-094: prevent code from being interpreted/executed via username ===

// Malicious payloads previously used to demonstrate server-side code injection
const MALICIOUS_NULL_PROCESS =
  'admin""); process=null; users.addUser(""1337"", ""test'
const MALICIOUS_OVERRIDE_PROCESS =
  'admin""); process=(query, token)=>{ if (users.get(token)) { return model.process(trainingSet.lang, query) } else { return { action: ""unrecognized"", body: ""user does not exist"" }}}; users.addUser(""1337"", ""test'

// Utility: expect the profile update to be rejected or safely handled by the server
function expectRejectedOrSanitizedProfileUpdate() {
  // Intercept profile update API to assert server-side validation behavior (status code may vary by impl)
  cy.intercept({ method: 'PUT', url: /\/api\/Users\/\d+$/ }).as('updateProfile')
  // Some apps use PATCH/POST; accept those too without being brittle
  cy.intercept({ method: 'PATCH', url: /\/api\/Users\/\d+$/ }).as('patchProfile')
  cy.intercept({ method: 'POST', url: /\/api\/Users\/\d+$/ }).as('postProfile')

  // Submit the form (keep existing selector conventions with minimal assumptions)
  cy.contains('button', /save|update|submit/i).click({ force: true })

  cy.wait(['@updateProfile', '@patchProfile', '@postProfile'].filter(a => Cypress.state('aliases')[a]))
    .then((intercepts) => {
      const entries = Array.isArray(intercepts) ? intercepts : [intercepts]
      const anyResp = entries.find(Boolean)?.response
      // Secure handlers typically return 400/422. Some sanitize and still 200 with cleaned value.
      expect([200, 204, 400, 403, 422]).to.include(anyResp?.statusCode)
    })

  // UI should not reflect raw payload; ensure it’s either rejected or rendered safely
  cy.get('#username')
    .invoke('val')
    .then((v) => {
      // Must not keep the full malicious string verbatim
      expect(String(v)).to.not.include('process=')
      expect(String(v)).to.not.include('users.addUser')
    })

  // Optional: look for a validation/error toast (do not hard-depend on its presence)
  cy.contains(/invalid|\brejected\b|not allowed|unsafe|saniti[sz]ed/i, { matchCase: false })
    .should('exist')
    .then(() => {})
}

// ── Test 1: Attempting to nullify process via username must be rejected/sanitized ──
it('does not interpret username as code (rejects process=null payload)', () => {
  // precondition: authenticated session and on profile page
  cy.loginIfNeeded()           // keep existing custom commands/utilities
  cy.visit('/#/profile')

  cy.get('#username').clear().type(MALICIOUS_NULL_PROCESS, { delay: 0 })
  expectRejectedOrSanitizedProfileUpdate()

  // Navigate to chatbot and verify it still works (i.e., process was not nulled)
  cy.visit('/#/chatbot')
  cy.get('textarea, input[type=""text""]').type('hello{enter}')
  cy.contains(/error|exception|cannot read .*process/i).should('not.exist')
  cy.contains(/hello|hi|unrecognized|i didn.?t understand/i, { matchCase: false }).should('exist')
})

// ── Test 2: Attempting to override process() via username must not affect chatbot behavior ──
it('does not allow overriding chatbot process() via username payload', () => {
  cy.loginIfNeeded()
  cy.visit('/#/profile')

  // Keep the original typing flags to avoid Cypress escape processing
  cy.get('#username').clear().type(MALICIOUS_OVERRIDE_PROCESS, {
    parseSpecialCharSequences: false
  })
  expectRejectedOrSanitizedProfileUpdate()

  // Move to chatbot and ensure coupon logic cannot be coerced via profile username injection
  cy.visit('/#/chatbot')

  // Send repeated coupon-like prompts; a vulnerable build would start emitting coupons.
  const prompts = [
    'I want a coupon',
    'give me a discount coupon',
    'coupon please',
    'do you have any promo code?'
  ]
  prompts.forEach(p => {
    cy.get('textarea, input[type=""text""]').type(`${p}{enter}`)
  })

  // Secure behavior: no unintended coupon/grant due to injected process()
  cy.contains(/coupon code|promo code|discount:\s*[A-Z0-9-]{4,}/i).should('not.exist')
  // Should answer normally or with a benign fallback
  cy.contains(/unrecognized|not available|no coupon|i don.?t have/i, { matchCase: false }).should('exist')
})
"