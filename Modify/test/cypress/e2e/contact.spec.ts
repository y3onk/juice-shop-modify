"cy.get('#captcha')
  .should('be.visible')
  .invoke('text')
  .then((val) => {
    cy.get('#captchaControl').clear();
    // compute captcha answer safely
    let answer: string;
    try {
      const num = safeEvalArithmetic(String(val));
      // keep original test behavior (string answer)
      answer = num.toString();
    } catch (err) {
      // If captcha contains unexpected content, fail the test early with a clear message.
      // This keeps functionality deterministic and avoids executing arbitrary code.
      throw new Error(`Unable to evaluate captcha expression safely: ${String(err)}`);
    }
    // proceed to type the computed answer
    cy.get('#captchaControl').type(answer);"