const tap = require('tap')
const rewiremock = require('rewiremock/node')

// require target module with mocked dependencies
const AuthTokens = rewiremock.proxy('../src/index.js', () => ({
  jose: {
    JWK: {
      asKey ({ kty, use, k }) {
        return {
          kty,
          use,
          kid: k
        }
      }
    },
    JWT: {
      sign (payload, key) {
        return 'STUB_SIGNED_PAYLOAD'
      },
      verify (jwt, key) {
        return {
          userId: 123456789
        }
      }
    },
    JWE: {
      encrypt (payload, key) {
        return 'STUB_ACCESS_TOKEN'
      },
      decrypt (jwe, key) {
        return 'STUB_ACCESS_TOKEN'
      }
    }
  },
  './../src/storage/MemoryStorage': class MemoryStorage {
    constructor () {
      this.usersTokenList = {}
    }

    getRefreshToken (userId) {
      const users = {
        123456789: {
          refreshToken: 'refreshToken',
          csrfToken: 'csrfToken'
        }
      }

      return users[userId]
    }
  },
  './../src/storage/RedisStorage': class RedisStorage {
    constructor () {
      this.redis = {}
    }
  }
}))

const AUTH_TOKENS_OPTIONS = {
  ACCESS_TOKEN_NAME: 'access_token_name',
  REFRESH_TOKEN_NAME: 'refresh_token_name',
  CSRF_TOKEN_NAME: 'csrf_token_name'
}

tap.test('AuthTokens instance with default options', (test) => {
  const authTokens = new AuthTokens()

  test.match(
    authTokens,
    {
      options: {},
      storage: {},
      SIGN_KEY: {},
      ENCODE_KEY: {}
    }
  )
  test.end()
})

tap.test('AuthTokens instance with MemoryStorage', (test) => {
  const authTokens = new AuthTokens()

  test.match(
    authTokens,
    {
      options: {},
      storage: {
        usersTokenList: {}
      },
      SIGN_KEY: {},
      ENCODE_KEY: {}
    }
  )
  test.end()
})

tap.test('AuthTokens instance with RedisStorage', (test) => {
  const authTokens = new AuthTokens({
    redis: {}
  })

  test.match(
    authTokens,
    {
      options: {},
      storage: {
        redis: {}
      },
      SIGN_KEY: {},
      ENCODE_KEY: {}
    }
  )
  test.end()
})

tap.test('generateTokens()', (test) => {
  const authTokens = new AuthTokens()

  const {
    accessToken,
    accessTokenExpiresIn,
    refreshToken,
    csrfToken
  } = authTokens.generateTokens(123456789)

  test.type(accessToken, 'string')
  test.type(accessTokenExpiresIn, 'number')
  test.type(refreshToken, 'string')
  test.type(csrfToken, 'string')
  test.end()
})

tap.test('generateAccessTokenCookie()', (test) => {
  const authTokens = new AuthTokens({
    ...AUTH_TOKENS_OPTIONS
  })

  const accessToken = 'accessToken'
  const accessTokenCookie = authTokens.generateAccessTokenCookie(accessToken)

  test.match(
    accessTokenCookie,
    [
      AUTH_TOKENS_OPTIONS.ACCESS_TOKEN_NAME,
      accessToken,
      {}
    ]
  )
  test.end()
})

tap.test('generateRefreshTokenCookie()', (test) => {
  const authTokens = new AuthTokens({
    ...AUTH_TOKENS_OPTIONS
  })

  const refreshToken = 'refreshToken'
  const refreshTokenCookie = authTokens.generateRefreshTokenCookie(refreshToken)

  test.match(
    refreshTokenCookie,
    [
      AUTH_TOKENS_OPTIONS.REFRESH_TOKEN_NAME,
      refreshToken,
      {}
    ]
  )
  test.end()
})

tap.test('generateCsrfTokenCookie()', (test) => {
  const authTokens = new AuthTokens({
    ...AUTH_TOKENS_OPTIONS
  })

  const csrfToken = 'csrfToken'
  const csrfTokenCookie = authTokens.generateCsrfTokenCookie(csrfToken)

  test.match(
    csrfTokenCookie,
    [
      AUTH_TOKENS_OPTIONS.CSRF_TOKEN_NAME,
      csrfToken,
      {}
    ]
  )
  test.end()
})

tap.test('generateCookies()', (test) => {
  const authTokens = new AuthTokens()

  const accessToken = 'accessToken'
  const refreshToken = 'refreshToken'
  const csrfToken = 'csrfToken'

  test.test('accessToken cookie generated', test => {
    const cookies = authTokens.generateCookies({
      accessToken
    })

    test.match(
      cookies,
      {
        accessTokenCookie: []
      }
    )
    test.end()
  })

  test.test('refreshToken cookie generated', test => {
    const cookies = authTokens.generateCookies({
      refreshToken
    })

    test.match(
      cookies,
      {
        refreshTokenCookie: []
      }
    )
    test.end()
  })

  test.test('csrfToken cookie generated', test => {
    const cookies = authTokens.generateCookies({
      csrfToken
    })

    test.match(
      cookies,
      {
        csrfTokenCookie: []
      }
    )
    test.end()
  })

  test.end()
})

tap.test('verifyRefreshToken()', (test) => {
  const authTokens = new AuthTokens()

  const refreshToken = 'refreshToken'
  const csrfToken = 'csrfToken'

  test.test('Refresh token not found', test => {
    test.throws(
      () => {
        authTokens.verifyRefreshToken(987654321)
      },
      new Error('Refresh token not found')
    )

    test.end()
  })

  test.test('Refresh token is invalid', test => {
    test.throws(
      () => {
        authTokens.verifyRefreshToken(123456789, 'invalidRefreshToken')
      },
      new Error('Refresh token is invalid')
    )

    test.end()
  })

  test.test('CSRF token is invalid', test => {
    test.throws(
      () => {
        authTokens.verifyRefreshToken(123456789, refreshToken, 'invalidCsrfToken')
      },
      new Error('CSRF token is invalid')
    )

    test.end()
  })

  test.test('Refresh token is valid', test => {
    const isValidRefresToken = authTokens.verifyRefreshToken(
      123456789,
      refreshToken,
      csrfToken
    )

    test.equal(isValidRefresToken, true)
    test.end()
  })

  test.end()
})

tap.test('verifyAccessToken()', (test) => {
  const authTokens = new AuthTokens()

  const accessToken = 'accessToken'

  const validatedAccessToken = authTokens.verifyAccessToken(accessToken)

  test.match(
    validatedAccessToken,
    {
      userId: 123456789
    }
  )
  test.end()
})
