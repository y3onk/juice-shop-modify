 challengeUtils.solveIf(challenges.negativeOrderChallenge, () => { return totalPrice < 0 })

          if (req.body.UserId) {
            if (req.body.orderDetails && req.body.orderDetails.paymentId === 'wallet') {
              const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
              if ((wallet != null) && wallet.balance >= totalPrice) {
                WalletModel.decrement({ balance: totalPrice }, { where: { UserId: req.body.UserId } }).catch((error: unknown) => {
                  next(error)
                })
              } else {
                next(new Error('Insufficient wallet balance.'))
              }
            }
            WalletModel.increment({ balance: totalPoints }, { where: { UserId: req.body.UserId } }).catch((error: unknown) => {
              next(error)
            })
          }