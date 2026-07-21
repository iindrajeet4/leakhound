// FAKE secrets for testing leakhound. None of these are real credentials.
module.exports = {
  awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE', // classic AWS docs example key
  googleApiKey: 'AIzaSyA1234567890abcdefABCDEF-_9876543Z',
  githubToken: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456',
  stripeKey: 'sk_live_FAKEFAKEFAKE9999', // short fake — real Stripe keys are longer
  slack: 'xoxb-FAKE-FAKE-FAKE-FAKE',
  omise: 'skey_live_5fakefakefakefake1',
  // GB Prime Pay context line (heuristic rule):
  gbPrimePaySecretKey: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
};
