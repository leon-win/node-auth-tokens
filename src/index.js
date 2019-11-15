const crypto = require('crypto')
const { JWK, JWT, JWE } = require('jose')

const MemoryStorage = require('./storage/MemoryStorage')
const RedisStorage = require('./storage/RedisStorage')
const DEFAULT_OPTIONS = require('./defaultOptions')

const getRandomToken = (size) => {
  return crypto
    .randomBytes(size)
    .toString('hex')
}

class AuthTokens {
  constructor (options = {}) {
    this.options = {
      ...DEFAULT_OPTIONS,
      ...options
    }

    if (options.redis) {
      this.storage = new RedisStorage(
        options.redis,
        this.options.refreshTokenMaxAge / 1000
      )
    } else {
      this.storage = new MemoryStorage()
    }

    this.signKey = JWK.asKey({
      kty: 'oct',
      use: 'sig',
      k: this.options.signSecret
    })

    this.encodeKey = JWK.asKey({
      kty: 'oct',
      use: 'enc',
      k: this.options.encodeSecret
    })
  }

  setTokens (userId) {
    const accessTokenExpiresIn = Date.now() + this.options.accessTokenMaxAge
    const csrfToken = getRandomToken(this.options.randomBytesSize)
    const refreshTokenValue = getRandomToken(this.options.randomBytesSize)

    const accessToken = JWE.encrypt(
      JWT.sign(
        {
          userId,
          exp: accessTokenExpiresIn
        },
        this.signKey
      ),
      this.encodeKey
    )
    const refreshToken = JWE.encrypt(
      JWT.sign(
        {
          userId,
          value: refreshTokenValue,
          csrfToken
        },
        this.signKey
      ),
      this.encodeKey
    )

    this.storage.setRefreshToken(
      userId,
      refreshTokenValue,
      csrfToken
    )

    return {
      accessToken,
      accessTokenExpiresIn,
      refreshToken
    }
  }

  refreshTokens (currentRefreshToken) {
    const refreshTokenData = this.verifyRefreshToken(currentRefreshToken)
    const accessTokenExpiresIn = Date.now() + this.options.accessTokenMaxAge
    const csrfToken = getRandomToken(this.options.randomBytesSize)

    const accessToken = JWE.encrypt(
      JWT.sign(
        {
          userId: refreshTokenData.userId,
          exp: accessTokenExpiresIn
        },
        this.signKey
      ),
      this.encodeKey
    )
    const refreshToken = JWE.encrypt(
      JWT.sign(
        {
          userId: refreshTokenData.userId,
          value: refreshTokenData.value,
          csrfToken
        },
        this.signKey
      ),
      this.encodeKey
    )

    this.storage.updateCsrfToken(
      refreshTokenData.userId,
      csrfToken
    )

    return {
      accessToken,
      accessTokenExpiresIn,
      refreshToken
    }
  }

  verifyToken (token) {
    const decryptedToken = JWE.decrypt(
      token,
      this.encodeKey
    )

    return JWT.verify(
      decryptedToken.toString(),
      this.signKey
    )
  }

  verifyAccessToken (accessToken) {
    return this.verifyToken(accessToken)
  }

  verifyRefreshToken (refreshToken) {
    const refreshTokenData = this.verifyToken(refreshToken)
    const savedRefreshToken = this.storage.getRefreshToken(refreshTokenData.userId)

    if (!savedRefreshToken) {
      throw new Error('Refresh token not found')
    }

    if (savedRefreshToken.refreshToken !== refreshTokenData.value) {
      throw new Error('Refresh token is invalid')
    }

    if (savedRefreshToken.csrfToken !== refreshTokenData.csrfToken) {
      throw new Error('CSRF token is invalid')
    }

    return refreshTokenData
  }

  deleteRefreshToken (refreshToken) {
    const refreshTokenData = this.verifyToken(refreshToken)

    return this.storage.deleteRefreshToken(refreshTokenData.userId)
  }
}

module.exports = AuthTokens
