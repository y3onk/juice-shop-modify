"// POST /Products — keep API the same; server must sanitize on store/echo (CWE-079 covered server-side)
return frisby.post(API_URL + '/Products', {
  headers: authHeader, // authenticated create (unchanged)
  body: {
    name: 'XSS Juice (42ml)',
    description: '<iframe src=""javascript:alert(`xss`)"">', // server will sanitize before storing/returning
    price: 9999.99,
    image: 'xss3juice.jpg'
  }
})

// PUT /Products/:id — require auth header and avoid sending raw HTML (CWE-862 & defense-in-depth for CWE-079)
const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;')
   .replace(/</g, '&lt;')
   .replace(/>/g, '&gt;')
   .replace(/""/g, '&quot;')

return frisby.put(API_URL + '/Products/' + tamperingProductId, {
  headers: { ...authHeader, ...jsonHeader }, // ensure Authorization is present (fixes missing access control)
  body: {
    // send safely-encoded content; server will still sanitize/validate before storing
    description: escapeHtml('<a href=""http://kimminich.de"" target=""_blank"">More...</a>')
  }
})
"