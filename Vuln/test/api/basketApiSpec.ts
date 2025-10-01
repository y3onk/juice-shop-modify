  it('POST placing an order for a non-existing basket fails', () => {
    return frisby.post(REST_URL + '/basket/42/checkout', { headers: authHeader })
      .expect('status', 500)
      .expect('bodyContains', 'Error: Basket with id=42 does not exist.')
  })

  it('POST placing an order for a basket with a negative total cost is possible', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: { BasketId: 2, ProductId: 10, quantity: -100 }
    })
      .expect('status', 200)
      .then(() => {
        return frisby.post(REST_URL + '/basket/3/checkout', { headers: authHeader })
          .expect('status', 200)
          .then(({ json }) => {
            expect(json.orderConfirmation).toBeDefined()
          })
      })
  })