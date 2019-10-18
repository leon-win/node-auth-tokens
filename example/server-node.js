const fs = require('fs')
const http = require('http')
const Cookies = require('cookies')
const Redis = require('ioredis')

const NodeAuthTokens = require('../src/index')

const USERS = {
  username1: 'password1',
  username2: 'password2'
}

const NODE_AUTH_OPTIONS = {
  ACCESS_TOKEN_NAME: 'ACCESS_TOKEN_NAME',
  REFRESH_TOKEN_NAME: 'REFRESH_TOKEN_NAME',
  CSRF_TOKEN_NAME: 'CSRF_TOKEN_NAME'
}

const redis = new Redis()
const authTokens = new NodeAuthTokens({
  ...NODE_AUTH_OPTIONS,
  redis
})

const server = http
  .createServer(requestHandler)
  .listen(12345, listenHandler)

function listenHandler (error) {
  if (error) {
    return console.error(error)
  }

  console.info(`node-auth-tokens example server is running on http://localhost:${server.address().port}/`)
}

function requestHandler (request, response) {
  let body = []

  response.on('error', (error) => {
    console.error(error)
  })

  request
    .on('error', (error) => {
      console.error(error)

      response.statusCode = 400
      response.end()
    })
    .on('data', (chunk) => {
      body.push(chunk)
    })
    .on('end', () => {
      if (body.length) {
        body = JSON.parse(
          Buffer.concat(body).toString()
        )
      }

      switch (request.url) {
        case '/':
          fs.createReadStream(`${__dirname}/static/index.html`)
            .pipe(response)
          break

        case '/app.js':
          fs.createReadStream(`${__dirname}/static/app.js`)
            .pipe(response)
          break

        case '/app.css':
          fs.createReadStream(`${__dirname}/static/app.css`)
            .on('open', () => {
              response.writeHead(200, { 'Content-Type': 'text/css' })
            })
            .pipe(response)
          break

        case '/api/login':
          processLogin(request, response, body)
          break

        case '/api/logout':
          processLogout(request, response, body)
          break

        case '/api/refresh':
          processRefresh(request, response, body)
          break

        case '/api/protected':
          processProtected(request, response, body)
          break

        default:
          response.writeHead(404)
          response.end()
      }
    })
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
      refreshToken,
      csrfToken
    } = authTokens.generateTokens(username)

    authTokens.storage.setRefreshToken(
      username,
      refreshToken,
      csrfToken
    )

    const {
      accessTokenCookie,
      refreshTokenCookie,
      csrfTokenCookie
    } = authTokens.generateCookies({
      accessToken,
      refreshToken,
      csrfToken
    })
    const cookies = new Cookies(request, response)

    cookies.set(...accessTokenCookie)
    cookies.set(...refreshTokenCookie)
    cookies.set(...csrfTokenCookie)

    responseWithBody(
      response,
      {
        message: 'Logged in',
        accessTokenExpiresIn
      }
    )
  } else {
    responseUnauthorized(response)
  }
}

function processLogout (request, response) {
  const cookies = new Cookies(request, response)
  const accessToken = cookies.get(NODE_AUTH_OPTIONS.ACCESS_TOKEN_NAME)

  try {
    const data = authTokens.verifyAccessToken(accessToken)

    authTokens.storage.deleteRefreshToken(data.userId)

    cookies.set(
      NODE_AUTH_OPTIONS.ACCESS_TOKEN_NAME,
      '',
      {
        expires: Date.now(1),
        maxAge: Date.now(1)
      }
    )
    cookies.set(
      NODE_AUTH_OPTIONS.REFRESH_TOKEN_NAME,
      '',
      {
        expires: Date.now(1),
        maxAge: Date.now(1)
      }
    )
    cookies.set(
      NODE_AUTH_OPTIONS.CSRF_TOKEN_NAME,
      '',
      {
        expires: Date.now(1),
        maxAge: Date.now(1)
      }
    )
  } catch {
    responseUnauthorized(response)
  }

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
  const currentAccessToken = cookies.get(NODE_AUTH_OPTIONS.ACCESS_TOKEN_NAME)
  const currentRefreshToken = cookies.get[NODE_AUTH_OPTIONS.REFRESH_TOKEN_NAME]
  const currentCsrfToken = cookies.get[NODE_AUTH_OPTIONS.CSRF_TOKEN_NAME]

  let accessTokenData
  let userId

  try {
    accessTokenData = authTokens.verifyAccessToken(currentAccessToken)
    userId = accessTokenData.userId
    authTokens.verifyRefreshToken(userId, currentRefreshToken, currentCsrfToken)
  } catch {
    return responseUnauthorized(response)
  }

  const {
    accessToken,
    accessTokenExpiresIn,
    csrfToken
  } = authTokens.generateTokens(userId)

  const {
    accessTokenCookie,
    csrfTokenCookie
  } = authTokens.generateCookies({ accessToken, csrfToken })

  authTokens.storage.updateCsrfToken(userId, csrfToken)

  cookies.set(...accessTokenCookie)
  cookies.set(...csrfTokenCookie)

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
  const accessToken = cookies.get(NODE_AUTH_OPTIONS.ACCESS_TOKEN_NAME)

  try {
    authTokens.verifyAccessToken(accessToken)
  } catch {
    return responseUnauthorized(response)
  }

  responseWithBody(
    response,
    { message: 'Some protected data' }
  )
}
