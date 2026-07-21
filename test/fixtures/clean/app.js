// A perfectly innocent file. No secrets here.
const config = {
  name: 'clean-app',
  port: 3000,
  password: 'changeme', // low-entropy placeholder, should NOT be flagged
};

function greet(who) {
  return `hello ${who}`;
}

module.exports = { config, greet };
