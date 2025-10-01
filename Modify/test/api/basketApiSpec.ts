"it('POST placing an order for a non-existing basket returns a generic 404 without internal details', () => {
  return frisby.post(REST_URL + '/basket/42/checkout', { headers: authHeader })
    .expect('status', 404) // Avoid leaking internals via 500
    .expect('bodyContains', 'Basket not found') // Generic message (no IDs, no stack)
})

it('POST adding a BasketItem with a negative quantity is rejected and checkout cannot proceed', () => {
  return frisby.post(API_URL + '/BasketItems', {
    headers: authHeader,
    body: { BasketId: 2, ProductId: 10, quantity: -100 }
  })
    .expect('status', 400) // Reject negative quantity at input validation
    .expect('bodyContains', 'Invalid quantity') // Clear but generic validation error
    .then(() => {
      // Attempting checkout on the same basket should also be prevented
      return frisby.post(REST_URL + '/basket/2/checkout', { headers: authHeader })
        .expect('status', 400) // Checkout blocked due to invalid basket state/contents
    })
})
"