const fs = require('fs')
const http = require('http')

const {
  processLogin,
  processLogout,
  processRefresh,
  processProtected
} = require('./handlers')

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
