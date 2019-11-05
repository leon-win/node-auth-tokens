const crypto = require('crypto')
const { JWK, JWT, JWE } = require('jose')

const MemoryStorage = require('./storage/MemoryStorage')
const RedisStorage = require('./storage/RedisStorage')

const DEFAULT_OPTIONS = {
  cookieOptions: {
    domain: 'localhost',
    httpOnly: true,
    path: '/',
    sameSite: 'strict',
    secure: false
  },

  randomBytesSize: 64,

  signSecret: 'SIGN_SECRET',
  encodeSecret: 'ENCODE_SECRET',

  accessTokenName: 'ACCESS_TOKEN_NAME',
  refreshTokenName: 'REFRESH_TOKEN_NAME',
  csrfTokenName: 'CSRF_TOKEN_NAME',

  accessTokenMaxAge: 5 * 60 * 1000, // 5 minutes in ms
  refreshTokenMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  csrfTokenMaxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
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
        this.options.refreshTokenMaxAge / 1000
      )
    } else {
      this.storage = new MemoryStorage()
    }

    this.SIGN_KEY = JWK.asKey({
      kty: 'oct',
      use: 'sig',
      k: this.options.signSecret
    })

    this.ENCODE_KEY = JWK.asKey({
      kty: 'oct',
      use: 'enc',
      k: this.options.encodeSecret
    })
  }

  generateTokens (userId) {
    const exp = Date.now() + this.options.accessTokenMaxAge

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
      refreshToken: getRandomToken(this.options.randomBytesSize),
      csrfToken: getRandomToken(this.options.randomBytesSize)
    }
  }

  generateCookies ({ accessToken, refreshToken, csrfToken }) {
    const cookies = {}

    if (accessToken) {
      cookies.accessTokenCookie = this.generateAccessTokenCookie(accessToken)
    }

    if (refreshToken) {
      cookies.refreshTokenCookie = this.generateRefreshTokenCookie(refreshToken)
    }

    if (csrfToken) {
      cookies.csrfTokenCookie = this.generateCsrfTokenCookie(csrfToken)
    }

    return cookies
  }

  generateAccessTokenCookie (accessToken) {
    return [
      this.options.accessTokenName,
      accessToken,
      {
        ...this.options.cookieOptions,
        maxAge: this.options.accessTokenMaxAge
      }
    ]
  }

  generateRefreshTokenCookie (refreshToken) {
    return [
      this.options.refreshTokenName,
      refreshToken,
      {
        ...this.options.cookieOptions,
        maxAge: this.options.refreshTokenMaxAge
      }
    ]
  }

  generateCsrfTokenCookie (csrfToken) {
    return [
      this.options.csrfTokenName,
      csrfToken,
      {
        ...this.options.cookieOptions,
        maxAge: this.options.csrfTokenMaxAge
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
