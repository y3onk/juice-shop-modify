//CWE-943 snippet
    return frisby.patch(`${REST_URL}/products/reviews`, {
      headers: authHeader,
      body: {
        id: { $ne: -1 },
        message: 'trololololololololololololololololololololololololololol'
      }
    })
//CWE-798 snippet
    return frisby.post(`${REST_URL}/user/login`, {
      headers: jsonHeader,
      body: {
        email: 'bjoern.kimminich@gmail.com',
        password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI='
      }
    })