description: {
        type: DataTypes.STRING,
        set (description: string) {
          if (utils.isChallengeEnabled(challenges.restfulXssChallenge)) {
            challengeUtils.solveIf(challenges.restfulXssChallenge, () => {
              return utils.contains(
                description,
                '<iframe src="javascript:alert(`xss`)">'
              )
            })
          } else {
            description = security.sanitizeSecure(description)
          }
          this.setDataValue('description', description)
        }
      },