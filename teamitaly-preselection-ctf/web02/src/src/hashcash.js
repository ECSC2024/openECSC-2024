const crypto = require('crypto');

function checkZeroBits(data, bytes, bits) {
  // check firsts bits equal to 0
  let last = bytes - 1;
  return data.slice(0, last) == '\x00'.repeat(last) &&
    data.slice(-1)[0] >> (bytes * 8 - bits) == 0;
}

function verify_pow(bits, pow, solution) {
  let bytes = parseInt(bits / 8 + (8 - (bits % 8)) / 8);
  // check if pow is the same of solution
  let part = solution.split(':');
  if (part.length !== 7 || part[3] !== pow) {
    return false;
  }

  //sha1 of solution
  let hash = crypto.createHash('sha1').update(solution).digest();
  //substring by bytes
  let prefix = hash.slice(0, bytes);

  return checkZeroBits(prefix, bytes, bits);
}

// export
module.exports = verify_pow;
