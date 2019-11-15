const tap = require('tap')
const rewiremock = require('rewiremock/node')

// require target module with mocked dependencies
const AuthTokens = rewiremock.proxy('./../src/index.js', () => ({
  jose: {
    JWK: {
      asKey ({ kty, use, k }) {
        return { kty, use, kid: k }
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
          refreshToken: 'refreshTokenValue',
          csrfToken: 'csrfToken'
        }
      }

      return users[userId]
    }

    setRefreshToken () {}
  },
  './../src/storage/RedisStorage': class RedisStorage {
    constructor () {
      this.redis = {}
    }
  }
}))

tap.test('AuthTokens instance with default options', (test) => {
  const authTokens = new AuthTokens()

  test.match(
    authTokens,
    {
      options: {},
      storage: {},
      signKey: {},
      encodeKey: {}
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
      signKey: {},
      encodeKey: {}
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
      signKey: {},
      encodeKey: {}
    }
  )
  test.end()
})

tap.test('setTokens()', (test) => {
  const authTokens = new AuthTokens()

  const {
    accessToken,
    accessTokenExpiresIn,
    refreshToken
  } = authTokens.setTokens(123456789)

  test.type(accessToken, 'string')
  test.type(accessTokenExpiresIn, 'number')
  test.type(refreshToken, 'string')
  test.end()
})

tap.test('verifyAccessToken()', (test) => {
  const authTokens = new AuthTokens()

  const accessToken = 'accessToken'

  const accessTokenData = authTokens.verifyAccessToken(accessToken)

  test.match(
    accessTokenData,
    {
      userId: 123456789
    }
  )
  test.end()
})

tap.test('verifyRefreshToken()', (test) => {
  const authTokens = new AuthTokens()

  const obsoleteRrefreshToken = 'obsoleteRrefreshToken'
  const invalidRefreshToken = 'invalidRefreshToken'
  const refreshTokenWithInvalidCsrf = 'refreshTokenWithInvalidCsrf'
  const validRefreshToken = 'validRefreshToken'

  // mock authTokens.verifyToken() method
  authTokens.verifyToken = (token) => {
    if (token === obsoleteRrefreshToken) {
      return {
        userId: 987654321
      }
    }

    if (token === invalidRefreshToken) {
      return {
        userId: 123456789,
        value: 'invalidRefreshTokenValue'
      }
    }

    if (token === refreshTokenWithInvalidCsrf) {
      return {
        userId: 123456789,
        value: 'refreshTokenValue',
        csrfToken: 'invalidCsrfToken'
      }
    }

    if (token === validRefreshToken) {
      return {
        userId: 123456789,
        value: 'refreshTokenValue',
        csrfToken: 'csrfToken'
      }
    }
  }

  test.test('Refresh token not found', test => {
    test.throws(
      () => {
        authTokens.verifyRefreshToken(obsoleteRrefreshToken)
      },
      new Error('Refresh token not found')
    )
    test.end()
  })

  test.test('Refresh token is invalid', test => {
    test.throws(
      () => {
        authTokens.verifyRefreshToken(invalidRefreshToken)
      },
      new Error('Refresh token is invalid')
    )
    test.end()
  })

  test.test('CSRF token is invalid', test => {
    test.throws(
      () => {
        authTokens.verifyRefreshToken(refreshTokenWithInvalidCsrf)
      },
      new Error('CSRF token is invalid')
    )
    test.end()
  })

  test.test('Refresh token is valid', test => {
    test.match(
      authTokens.verifyRefreshToken(validRefreshToken),
      authTokens.verifyToken(validRefreshToken)
    )
    test.end()
  })

  test.end()
})
