const crypto = require('crypto')
const { JWK, JWT, JWE } = require('jose')

const MemoryStorage = require('./storage/MemoryStorage')
const RedisStorage = require('./storage/RedisStorage')

const DEFAULT_OPTIONS = {
  COOKIE_OPTIONS: {
    domain: 'localhost',
    httpOnly: true,
    path: '/',
    sameSite: 'strict',
    secure: false
  },

  RANDOM_BYTES_SIZE: 64,

  SIGN_SECRET: 'SIGN_SECRET',
  ENCODE_SECRET: 'ENCODE_SECRET',

  ACCESS_TOKEN_NAME: 'ACCESS_TOKEN_NAME',
  REFRESH_TOKEN_NAME: 'REFRESH_TOKEN_NAME',
  CSRF_TOKEN_NAME: 'CSRF_TOKEN_NAME',

  ACCESS_TOKEN_MAX_AGE: 5 * 60 * 1000, // 5 minutes in ms
  REFRESH_TOKEN_MAX_AGE: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  CSRF_TOKEN_MAX_AGE: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
}

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
        this.options.REFRESH_TOKEN_MAX_AGE / 1000
      )
    } else {
      this.storage = new MemoryStorage()
    }

    this.SIGN_KEY = JWK.asKey({
      kty: 'oct',
      use: 'sig',
      k: this.options.SIGN_SECRET
    })

    this.ENCODE_KEY = JWK.asKey({
      kty: 'oct',
      use: 'enc',
      k: this.options.ENCODE_SECRET
    })
  }

  generateTokens (userId) {
    const exp = Date.now() + this.options.ACCESS_TOKEN_MAX_AGE * 1000

    const accessToken = JWE.encrypt(
      JWT.sign(
        {
          userId,
          exp
        },
        this.SIGN_KEY
      ),
      this.ENCODE_KEY
    )

    return {
      accessToken,
      accessTokenExpiresIn: exp,
      refreshToken: getRandomToken(this.options.RANDOM_BYTES_SIZE),
      csrfToken: getRandomToken(this.options.RANDOM_BYTES_SIZE)
    }
  }

  generateCookies ({ accessToken, refreshToken, csrfToken }) {
    const cookies = {}

    if (accessToken) {
      cookies.accessTokenCookie = this.generateAccessTokenCookie(accessToken)
    }

    if (accessToken) {
      cookies.refreshTokenCookie = this.generateRefreshTokenCookie(refreshToken)
    }

    if (accessToken) {
      cookies.csrfTokenCookie = this.generateCsrfTokenCookie(csrfToken)
    }

    return cookies
  }

  generateAccessTokenCookie (accessToken) {
    return [
      this.options.ACCESS_TOKEN_NAME,
      accessToken,
      {
        ...this.options.COOKIE_OPTIONS,
        maxAge: this.options.ACCESS_TOKEN_MAX_AGE
      }
    ]
  }

  generateRefreshTokenCookie (refreshToken) {
    return [
      this.options.REFRESH_TOKEN_NAME,
      refreshToken,
      {
        ...this.options.COOKIE_OPTIONS,
        maxAge: this.options.REFRESH_TOKEN_MAX_AGE
      }
    ]
  }

  generateCsrfTokenCookie (csrfToken) {
    return [
      this.options.CSRF_TOKEN_NAME,
      csrfToken,
      {
        ...this.options.COOKIE_OPTIONS,
        maxAge: this.options.CSRF_TOKEN_MAX_AGE
      }
    ]
  }

  verifyRefreshToken (userId, refreshToken, csrfToken) {
    const savedToken = this.storage.getRefreshToken(userId)

    if (!savedToken) {
      throw new Error('Refresh token not found')
    }

    if (savedToken.refreshToken !== refreshToken) {
      throw new Error('Refresh token is invalid')
    }

    if (savedToken.csrfToken !== csrfToken) {
      throw new Error('CSRF token is invalid')
    }

    return true
  }

  verifyAccessToken (accessToken) {
    const decryptedAccessToken = JWE.decrypt(
      accessToken,
      this.ENCODE_KEY
    )

    return JWT.verify(
      decryptedAccessToken.toString(),
      this.SIGN_KEY
    )
  }
}

module.exports = AuthTokens
