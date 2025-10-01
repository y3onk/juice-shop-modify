"challengeUtils.solveIf(challenges.negativeOrderChallenge, () => { return totalPrice < 0 })

// ---- Fix: enforce ownership + validate totals to prevent IDOR & negative-credit flaws ----
const authUserId =
  (req as any).user?.data?.id ??
  (req as any).user?.id ??
  (res as any).locals?.user?.id ?? null

if (req.body.UserId) {
  // CWE-639: reject attempts to operate on a wallet that is not the authenticated user's
  if (authUserId == null || String(req.body.UserId) !== String(authUserId)) {
    return next(new Error('Unauthorized wallet access.'))
  }

  if (req.body.orderDetails && req.body.orderDetails.paymentId === 'wallet') {
    // CWE-840: totalPrice must be a finite, non-negative number (disallow negative-credit)
    if (!Number.isFinite(totalPrice) || totalPrice < 0) {
      return next(new Error('Invalid total price.'))
    }

    const wallet = await WalletModel.findOne({ where: { UserId: authUserId } })
    if ((wallet != null) && wallet.balance >= totalPrice) {
      WalletModel.decrement({ balance: totalPrice }, { where: { UserId: authUserId } }).catch((error: unknown) => {
        next(error)
      })
    } else {
      return next(new Error('Insufficient wallet balance.'))
    }
  }

  // Defensive: only add non-negative, finite points to the authenticated user's wallet
  const safePoints = Number(totalPoints)
  if (Number.isFinite(safePoints) && safePoints >= 0) {
    WalletModel.increment({ balance: safePoints }, { where: { UserId: authUserId } }).catch((error: unknown) => {
      next(error)
    })
  } else {
    return next(new Error('Invalid points amount.'))
  }
}
"