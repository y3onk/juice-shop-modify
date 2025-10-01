it('GET redirected to target URL in "to" parameter when a allow-listed URL is part of the query string', () => {
    return frisby.get(`${URL}/redirect?to=/score-board?satisfyIndexOf=https://github.com/juice-shop/juice-shop`)
      .expect('status', 200)
      .expect('header', 'content-type', /text\/html/)

 it('GET error message with information leakage when calling /redirect without query parameter', () => {
    return frisby.get(`${URL}/redirect`)
      .expect('status', 500)
      .expect('header', 'content-type', /text\/html/)