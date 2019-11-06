const Cookies = require('cookies')

const AuthTokens = require('../src/index')

const AUTH_OPTIONS = {
  accessTokenName: 'ACCESS_TOKEN_NAME',
  refreshTokenName: 'REFRESH_TOKEN_NAME'
}
const authTokens = new AuthTokens({
  ...AUTH_OPTIONS
})

const USERS = {
  username1: 'password1',
  username2: 'password2'
}

function responseWithBody (response, body) {
  response.writeHead(200, { 'Content-Type': 'application/json' })
  response.end(JSON.stringify({ ...body }))
}

function responseUnauthorized (response) {
  response.writeHead(401, { 'Content-Type': 'application/json' })
  response.end()
}

function processLogin (request, response, body) {
  const { username, password } = body

  if (USERS[username] && USERS[username] === password) {
    const {
      accessToken,
      accessTokenExpiresIn,
      refreshToken
    } = authTokens.setTokens(username)
    const {
      accessTokenCookie,
      refreshTokenCookie
    } = authTokens.generateCookies({
      accessToken,
      refreshToken
    })

    const cookies = new Cookies(request, response)
    cookies.set(...accessTokenCookie)
    cookies.set(...refreshTokenCookie)

    responseWithBody(
      response,
      {
        message: 'Logged in',
        accessTokenExpiresIn
      }
    )
    return
  }

  responseUnauthorized(response)
}

function processLogout (request, response) {
  const cookies = new Cookies(request, response)
  const refreshToken = cookies.get(AUTH_OPTIONS.refreshTokenName)

  if (authTokens.deleteRefreshToken(refreshToken)) {
    cookies.set(AUTH_OPTIONS.accessTokenName)
    cookies.set(AUTH_OPTIONS.refreshTokenName)

    responseWithBody(
      response,
      {
        message: 'Logged out',
        accessTokenExpiresIn: null
      }
    )
    return
  }

  responseUnauthorized(response)
}

function processRefresh (request, response, body) {
  const cookies = new Cookies(request, response)
  const currentRefreshToken = cookies.get(AUTH_OPTIONS.refreshTokenName)

  let accessToken
  let accessTokenExpiresIn
  let refreshToken

  try {
    ({
      accessToken,
      accessTokenExpiresIn,
      refreshToken
    } = authTokens.refreshTokens(currentRefreshToken))
  } catch (error) {
    console.error(error)

    responseUnauthorized(response)
    return
  }

  const {
    accessTokenCookie,
    refreshTokenCookie
  } = authTokens.generateCookies({
    accessToken,
    refreshToken
  })

  cookies.set(...accessTokenCookie)
  cookies.set(...refreshTokenCookie)

  responseWithBody(
    response,
    {
      message: 'Tokens refreshed',
      accessTokenExpiresIn
    }
  )
}

function processProtected (request, response, body) {
  const cookies = new Cookies(request, response)
  const accessToken = cookies.get(AUTH_OPTIONS.accessTokenName)

  try {
    authTokens.verifyAccessToken(accessToken)
  } catch (error) {
    console.error(error)

    responseUnauthorized(response)
    return
  }

  responseWithBody(
    response,
    { message: 'Some protected data' }
  )
}

module.exports = {
  processLogin,
  processLogout,
  processRefresh,
  processProtected
}
