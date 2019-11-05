module.exports = {
  cookieOptions: {
    domain: 'localhost',
    httpOnly: true,
    path: '/',
    sameSite: 'strict',
    secure: false
  },

  randomBytesSize: 64,

  signSecret: 'SIGN_SECRET',
  encodeSecret: 'ENCODE_SECRET',

  accessTokenName: 'ACCESS_TOKEN_NAME',
  refreshTokenName: 'REFRESH_TOKEN_NAME',
  csrfTokenName: 'CSRF_TOKEN_NAME',

  accessTokenMaxAge: 5 * 60 * 1000, // 5 minutes in ms
  refreshTokenMaxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
  csrfTokenMaxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
}
