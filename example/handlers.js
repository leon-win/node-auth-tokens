const Cookies = require('cookies')
const AuthTokens = require('../src/index')

// Naive implementaion of database with users data
const USERS = {
  username1: 'password1',
  username2: 'password2'
}

const ACCESS_TOKEN_NAME = 'ACCESS_TOKEN_NAME'
const REFRESH_TOKEN_NAME = 'REFRESH_TOKEN_NAME'

const AUTH_OPTIONS = {
  accessTokenMaxAge: 5 * 60 * 1000, // 5 minutes in ms
  refreshTokenMaxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
}

const authTokens = new AuthTokens({
  ...AUTH_OPTIONS
})

function generateCookie (name, value, maxAge) {
  return [
    name,
    value,
    {
      maxAge,
      domain: 'localhost',
      httpOnly: true,
      path: '/',
      sameSite: 'strict',
      secure: false // it should be true in production
    }
  ]
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

  // There should be real authentication logic
  if (USERS[username] && USERS[username] === password) {
    const {
      accessToken,
      accessTokenExpiresIn,
      refreshToken
    } = authTokens.setTokens(username)

    const cookies = new Cookies(request, response)
    const accessTokenCookie = generateCookie(ACCESS_TOKEN_NAME, accessToken, AUTH_OPTIONS.accessTokenMaxAge)
    const refreshTokenCookie = generateCookie(REFRESH_TOKEN_NAME, refreshToken, AUTH_OPTIONS.refreshTokenMaxAge)
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
  const refreshToken = cookies.get(REFRESH_TOKEN_NAME)

  if (!refreshToken) {
    responseUnauthorized(response)
    return
  }

  authTokens.deleteRefreshToken(refreshToken)

  // Clear cookies
  cookies.set(ACCESS_TOKEN_NAME)
  cookies.set(REFRESH_TOKEN_NAME)

  responseWithBody(
    response,
    {
      message: 'Logged out',
      accessTokenExpiresIn: null
    }
  )
}

function processRefresh (request, response, body) {
  const cookies = new Cookies(request, response)
  const currentRefreshToken = cookies.get(REFRESH_TOKEN_NAME)

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

  const accessTokenCookie = generateCookie(ACCESS_TOKEN_NAME, accessToken, AUTH_OPTIONS.accessTokenMaxAge)
  const refreshTokenCookie = generateCookie(REFRESH_TOKEN_NAME, refreshToken, AUTH_OPTIONS.refreshTokenMaxAge)
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
  const accessToken = cookies.get(ACCESS_TOKEN_NAME)

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
