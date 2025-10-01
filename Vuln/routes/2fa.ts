const userModel = await UserModel.findByPk(user.id)
    if (userModel == null) {
      throw new Error('No such user found!')
    }

    userModel.totpSecret = secret
    await userModel.save()
    security.authenticatedUsers.updateFrom(req, utils.queryResultToJson(userModel))

    res.status(200).send()
  } catch (error) {
    res.status(401).send()
  }