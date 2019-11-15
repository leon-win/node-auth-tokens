module.exports = {
  randomBytesSize: 64,

  signSecret: 'SIGN_SECRET',
  encodeSecret: 'ENCODE_SECRET',

  accessTokenMaxAge: 5 * 60 * 1000, // 5 minutes in ms
  refreshTokenMaxAge: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
}
