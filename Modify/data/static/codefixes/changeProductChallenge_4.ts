"/* Products: Only GET is allowed to view products; create/update restricted to admins */
app.post('/api/Products', security.isAuthorized(), security.isAdmin())
app.put('/api/Products/:id', security.isAuthorized(), security.isAdmin())
app.delete('/api/Products/:id', security.denyAll())
"