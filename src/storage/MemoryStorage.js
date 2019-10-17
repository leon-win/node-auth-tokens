class MemoryStorage {
  constructor () {
    this.usersTokenList = {}
  }

  getRefreshToken (userId) {
    return this.usersTokenList[userId]
  }

  setRefreshToken (userId, refreshToken, csrfToken) {
    this.usersTokenList[userId] = {
      refreshToken,
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
