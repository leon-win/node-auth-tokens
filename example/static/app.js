const username = document.getElementById('username')
const password = document.getElementById('password')
const log = document.getElementById('log')

const fetchProtectedData = () => {
  return window.fetch('/api/protected', {
    method: 'GET',
    credentials: 'include'
  })
    .then(response => {
      log.textContent += `/api/protected: ${response.status} (${response.statusText})`
      log.textContent += '\n'
    })
    .catch(error => {
      console.error('/api/protected error:', error)
    })
}

const tryFetchProtectedData = () => {
  const accessTokenExpiresIn = +window.sessionStorage.getItem('accessTokenExpiresIn')

  if (accessTokenExpiresIn && Date.now() <= accessTokenExpiresIn) {
    return fetchProtectedData()
  }

  return null
}

window.login = () => {
  return window.fetch('/api/login', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({
      username: username.value,
      password: password.value
    })
  })
    .then(response => {
      log.textContent += `/api/login: ${response.status} (${response.statusText})`
      log.textContent += '\n'

      if (response.status === 200) {
        return response.json()
      }
    })
    .then(data => {
      if (data && data.accessTokenExpiresIn) {
        window.sessionStorage.setItem('accessTokenExpiresIn', `${data.accessTokenExpiresIn}`)
      }
    })
    .catch(error => {
      console.error('/api/login error:', error)
    })
}

window.logout = () => {
  return window.fetch('/api/logout', {
    method: 'POST',
    credentials: 'include'
  })
    .then(response => {
      log.textContent += `/api/logout: ${response.status} (${response.statusText})`
      log.textContent += '\n'

      window.sessionStorage.removeItem('accessTokenExpiresIn')
    })
    .catch(error => {
      console.error('/api/logout error:', error)
    })
}

window.refreshTokens = () => {
  return window.fetch('/api/refresh', {
    method: 'POST',
    credentials: 'include'
  })
    .then(response => {
      log.textContent += `/api/refresh: ${response.status} (${response.statusText})`
      log.textContent += '\n'

      if (response.status === 200) {
        return response.json()
      }
    })
    .then(data => {
      if (data && data.accessTokenExpiresIn) {
        window.sessionStorage.setItem('accessTokenExpiresIn', `${data.accessTokenExpiresIn}`)
      }
    })
    .catch(error => {
      console.error('/api/refresh error:', error)
    })
}

window.getProtectedData = () => {
  if (tryFetchProtectedData() === null) {
    window.refreshTokens()
      .then(() => {
        tryFetchProtectedData()
      })
  }
}
