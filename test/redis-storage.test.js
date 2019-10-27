const tap = require('tap')

// require target module
const RedisStorage = require('../src/storage/RedisStorage')

// stub data
const refreshTokenExpiresIn = 604800
const userId = 123456789
const refreshToken = 'refreshToken'
const csrfToken = 'csrfToken'
const csrfToken2 = 'csrfToken2'

tap.test('RedisStorage instance', (test) => {
  test.test('Redis client instanсe is required', (test) => {
    test.throws(
      () => {
        const redisStorage = new RedisStorage()

        redisStorage.getRefreshToken(userId)
      },
      new Error('Redis client instanсe is required')
    )
    test.end()
  })

  test.test('refreshTokenExpiresIn param is required', (test) => {
    test.throws(
      () => {
        const redisStorage = new RedisStorage({})

        redisStorage.getRefreshToken(userId)
      },
      new Error('refreshTokenExpiresIn param is required')
    )
    test.end()
  })

  test.test('RedisStorage instance initialized', (test) => {
    const redisStorage = new RedisStorage({}, refreshTokenExpiresIn)

    test.match(
      redisStorage,
      {
        redis: {}
      }
    )
    test.end()
  })

  test.end()
})

tap.test('getRefreshToken()', (test) => {
  const redisStorage = new RedisStorage({}, refreshTokenExpiresIn)

  // mock ioredis hgetall() method
  redisStorage.redis = {
    hgetall (key) {
      const tokens = {
        'tokens:123456789': {
          refreshToken,
          csrfToken
        }
      }

      return tokens[key]
    }
  }

  test.match(
    redisStorage.getRefreshToken(userId),
    {
      refreshToken,
      csrfToken
    }
  )
  test.end()
})

tap.test('setRefreshToken()', (test) => {
  const redisStorage = new RedisStorage({}, refreshTokenExpiresIn)

  // mock ioredis multi(), hmset(), expire(), exec() methods
  redisStorage.redis = {
    tokens: {},
    refreshTokenExpiresIn,
    multi () {
      return this
    },
    hmset (key, { refreshToken, csrfToken }) {
      this.tokens[key] = { refreshToken, csrfToken }
      this.tokens[key].refreshToken = refreshToken
      this.tokens[key].csrfToken = csrfToken

      return this
    },
    expire (key, refreshTokenExpiresIn) {
      this.tokens[key].refreshTokenExpiresIn = refreshTokenExpiresIn
      return this
    },
    exec () {
      return this
    }
  }

  test.match(
    redisStorage.redis.tokens,
    {}
  )

  redisStorage.setRefreshToken(userId, refreshToken, csrfToken)

  test.match(
    redisStorage.redis.tokens,
    {
      'tokens:123456789': {
        refreshToken,
        csrfToken,
        refreshTokenExpiresIn
      }
    }
  )
  test.end()
})

tap.test('deleteRefreshToken()', (test) => {
  const redisStorage = new RedisStorage({}, refreshTokenExpiresIn)

  // mock ioredis del() method
  redisStorage.redis = {
    tokens: {
      'tokens:123456789': {
        refreshToken,
        csrfToken
      }
    },
    refreshTokenExpiresIn,
    del (key) {
      delete this.tokens[key]
    }
  }

  test.match(
    redisStorage.redis.tokens,
    {
      'tokens:123456789': {
        refreshToken,
        csrfToken
      }
    }
  )

  redisStorage.deleteRefreshToken(userId)

  test.match(
    redisStorage.redis.tokens,
    {}
  )
  test.end()
})

tap.test('updateCsrfToken()', (test) => {
  const redisStorage = new RedisStorage({}, refreshTokenExpiresIn)

  // mock ioredis hset() method
  redisStorage.redis = {
    tokens: {
      'tokens:123456789': {
        refreshToken,
        csrfToken
      }
    },
    refreshTokenExpiresIn,
    hset (key, csrfToken) {
      this.tokens[key].csrfToken = csrfToken2
    }
  }

  test.match(
    redisStorage.redis.tokens,
    {
      'tokens:123456789': {
        refreshToken,
        csrfToken
      }
    }
  )

  redisStorage.updateCsrfToken(userId, csrfToken2)

  test.match(
    redisStorage.redis.tokens,
    {
      'tokens:123456789': {
        refreshToken,
        csrfToken: csrfToken2
      }
    }
  )
  test.end()
})
