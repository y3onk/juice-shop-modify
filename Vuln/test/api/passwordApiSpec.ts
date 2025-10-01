return frisby.get(REST_URL + '/user/change-password?current=kunigunde&new=foo&repeat=foo', {
              headers: { Authorization: 'Bearer ' + json.authentication.token }
            })