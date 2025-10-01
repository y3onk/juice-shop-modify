.then(({ json: captchaAnswer }) => {
                return frisby.post(REST_URL + '/user/data-export', {
                  headers: { Authorization: 'Bearer ' + jsonLogin.authentication.token, 'content-type': 'application/json' },
                  body: {
                    answer: captchaAnswer.answer,
                    format: 1
                  }