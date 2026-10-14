const crypto = require('crypto');

/**
 * RFC4122 v4 UUID, built from crypto.randomBytes. Avoids depending on
 * crypto.randomUUID() (Node 14.17+ only) or an extra npm package, since
 * this project targets older Node installs too.
 */
function uuidv4() {
  const bytes = crypto.randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.substr(0, 8),
    hex.substr(8, 4),
    hex.substr(12, 4),
    hex.substr(16, 4),
    hex.substr(20, 12)
  ].join('-');
}

module.exports = { uuidv4 };
