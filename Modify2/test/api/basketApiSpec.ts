"it('POST placing an order for a non-existing basket returns 404 without leaking internals', () => {
  return frisby.post(REST_URL + '/basket/42/checkout', { headers: authHeader })
    .expect('status', 404)
    .then(({ body }) => {
      // Avoid CWE-209: generic message, no internal details
      expect(body).toContain('Basket not found')
      expect(body).not.toContain('Error:')
      expect(body).not.toContain('id=42')
    })
})

it('POST adding a negative-quantity BasketItem is rejected and checkout fails', () => {
  // Attempt to add an item with a negative quantity should fail validation
  return frisby.post(API_URL + '/BasketItems', {
    headers: authHeader,
    body: { BasketId: 2, ProductId: 10, quantity: -100 }
  })
    .expect('status', 400)
    .then(() => {
      // Subsequent checkout of the same basket must not succeed
      return frisby.post(REST_URL + '/basket/2/checkout', { headers: authHeader })
        .expect('status', 400)
        .then(({ json, body }) => {
          // Ensure no order confirmation is issued
          if (json) {
            expect(json.orderConfirmation).toBeUndefined()
          }
          // Ensure no misleading success text appears
          expect(body).not.toContain('orderConfirmation')
        })
    })
})
"