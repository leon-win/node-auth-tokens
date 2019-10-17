class RedisStorage {
  constructor (
    redisClientInstanсe,
    refreshTokenExpiresIn
  ) {
    if (!redisClientInstanсe) {
      throw new Error('Redis client instanсe is required')
    }

    this.redis = redisClientInstanсe
    this.refreshTokenExpiresIn = refreshTokenExpiresIn
  }

  getRefreshToken (userId) {
    return this.redis.hgetall(`tokens:${userId}`)
  }

  setRefreshToken (userId, refreshToken, csrfToken) {
    return this.redis.multi()
      .hmset(`tokens:${userId}`, { refreshToken, csrfToken })
      .expire(`tokens:${userId}`, this.refreshTokenExpiresIn)
      .exec()
  }

  deleteRefreshToken (userId) {
    return this.redis.del(`tokens:${userId}`)
  }

  updateCsrfToken (userId, csrfToken) {
    return this.redis.hset(`tokens:${userId}`, 'csrfToken', csrfToken)
  }
}

module.exports = RedisStorage
