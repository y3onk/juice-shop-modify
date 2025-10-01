"// Products: Only GET is allowed in order to view products
app.post('/api/Products', security.denyAll())
app.delete('/api/Products/:id', security.denyAll())

// Cards: require authentication for all endpoints (appendUserId ≠ auth)
app.post('/api/Cards', security.isAuthorized(), security.appendUserId())
app.get('/api/Cards', security.isAuthorized(), security.appendUserId(), payment.getPaymentMethods())
app.put('/api/Cards/:id', security.denyAll())
app.delete('/api/Cards/:id', security.isAuthorized(), security.appendUserId(), payment.delPaymentMethodById())
app.get('/api/Cards/:id', security.isAuthorized(), security.appendUserId(), payment.getPaymentMethodById())

app.post('/api/PrivacyRequests', security.isAuthorized())
app.get('/api/PrivacyRequests', security.denyAll())
app.use('/api/PrivacyRequests/:id', security.denyAll())

// Addresss: require authentication for all endpoints (appendUserId ≠ auth)
app.post('/api/Addresss', security.isAuthorized(), security.appendUserId())
app.get('/api/Addresss', security.isAuthorized(), security.appendUserId(), address.getAddress())
app.put('/api/Addresss/:id', security.isAuthorized(), security.appendUserId())
app.delete('/api/Addresss/:id', security.isAuthorized(), security.appendUserId(), address.delAddressById())
app.get('/api/Addresss/:id', security.isAuthorized(), security.appendUserId(), address.getAddressById())

app.get('/api/Deliverys', delivery.getDeliveryMethods())
app.get('/api/Deliverys/:id', delivery.getDeliveryMethod())
"