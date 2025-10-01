//CWE-079 snippet
return frisby.post(API_URL + '/Feedbacks', {
            headers: jsonHeader,
            body: {
              comment: 'The sanitize-html module up to at least version 1.4.2 has this issue: <<script>Foo</script>iframe src="javascript:alert(`xss`)">',
              rating: 1,
              captchaId: json.captchaId,
              captcha: json.answer
            }
          })
//CWE-639 snippet
return frisby.post(API_URL + '/Feedbacks', {
          headers: jsonHeader,
          body: {
            comment: 'Lousy crap! You use sequelize 1.7.x? Welcome to SQL Injection-land, morons! As if that is not bad enough, you use z85/base85 and hashids for crypto? Even MD5 to hash passwords! Srsly?!?!',
            rating: 1,
            UserId: 3,
            captchaId: json.captchaId,
            captcha: json.answer
          }
//CWE-209
.then(({ json }) => {
            expect(json.errors).toContain('SQLITE_CONSTRAINT: FOREIGN KEY constraint failed')
          })