const tap = require('tap')

// require target module
const MemoryStorage = require('./../src/storage/MemoryStorage')

// stub data
const userId = 123456789
const refreshToken = 'refreshToken'
const csrfToken = 'csrfToken'
const csrfToken2 = 'csrfToken2'

tap.test('MemoryStorage instance', (test) => {
  const memoryStorage = new MemoryStorage()

  test.match(
    memoryStorage.usersTokenList,
    {}
  )
  test.end()
})

tap.test('getRefreshToken()', (test) => {
  const memoryStorage = new MemoryStorage()

  memoryStorage.usersTokenList = {
    123456789: {
      refreshToken,
      csrfToken
    }
  }

  test.match(
    memoryStorage.getRefreshToken(userId),
    {
      refreshToken,
      csrfToken
    }
  )
  test.end()
})

tap.test('setRefreshToken()', (test) => {
  const memoryStorage = new MemoryStorage()

  test.match(
    memoryStorage,
    {}
  )

  memoryStorage.setRefreshToken(userId, refreshToken, csrfToken)

  test.match(
    memoryStorage.usersTokenList,
    {
      123456789: {
        refreshToken,
        csrfToken
      }
    }
  )
  test.end()
})

tap.test('deleteRefreshToken()', (test) => {
  const memoryStorage = new MemoryStorage()

  memoryStorage.usersTokenList = {
    123456789: {
      refreshToken,
      csrfToken
    }
  }

  test.match(
    memoryStorage.usersTokenList,
    {
      123456789: {
        refreshToken,
        csrfToken
      }
    }
  )

  memoryStorage.deleteRefreshToken(userId)

  test.match(
    memoryStorage.usersTokenList,
    {}
  )
  test.end()
})

tap.test('updateCsrfToken()', (test) => {
  const memoryStorage = new MemoryStorage()

  memoryStorage.usersTokenList = {
    123456789: {
      refreshToken,
      csrfToken
    }
  }

  test.match(
    memoryStorage.usersTokenList,
    {
      123456789: {
        refreshToken,
        csrfToken
      }
    }
  )

  memoryStorage.updateCsrfToken(userId, csrfToken2)

  test.match(
    memoryStorage.usersTokenList,
    {
      123456789: {
        refreshToken,
        csrfToken: csrfToken2
      }
    }
  )
  test.end()
})
