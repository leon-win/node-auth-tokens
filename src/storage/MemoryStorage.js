class MemoryStorage {
  constructor () {
    this.usersTokenList = {}
  }

  getRefreshToken (userId) {
    return this.usersTokenList[userId]
  }

  setRefreshToken (userId, refreshTokenValue, csrfToken) {
    this.usersTokenList[userId] = {
      refreshToken: refreshTokenValue,
      csrfToken
    }
  }

  deleteRefreshToken (userId) {
    delete this.usersTokenList[userId]
  }

  updateCsrfToken (userId, csrfToken) {
    this.usersTokenList[userId].csrfToken = csrfToken
  }
}

module.exports = MemoryStorage
