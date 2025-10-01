export const sendNotification = function (challenge: { difficulty?: number, key: any, name: any, description?: any }, isRestore: boolean) {
  if (!notSolved(challenge)) {
    const flag = utils.ctfFlag(challenge.name)
    const notification = {
      key: challenge.key,
      name: challenge.name,
      challenge: challenge.name + ' (' + entities.decode(sanitizeHtml(challenge.description, { allowedTags: [], allowedAttributes: {} })) + ')',
      flag,
      hidden: !config.get('challenges.showSolvedNotifications'),
      isRestore
    }
    const wasPreviouslyShown = notifications.some(({ key }) => key === challenge.key)
    notifications.push(notification)

    if (globalWithSocketIO.io && (isRestore || !wasPreviouslyShown)) {
      globalWithSocketIO.io.emit('challenge solved', notification)
    }
  }
}