"use strict";

const crypto = require('crypto');

const HASH_ALG = 'sha256';
const MAX_RANGE = 256;

/**
 * Generates a One-Time Pad encryption.
 * Takes a string or buffer and returns an object with ciphertext and key (both buffers).
 */
function makeOTP({ string, buffer }) {
  if ((!string && !buffer) || (!!string && !!buffer)) {
    throw new Error("Either string or buffer should be specified, but not both");
  }

  if (string) {
    buffer = Buffer.from(string);
  }

  let key = crypto.randomBytes(buffer.length);
  let ciphertext = Buffer.alloc(buffer.length);

  for (let i = 0; i < buffer.length; i++) {
    ciphertext[i] = buffer[i] ^ key[i];
  }

  return { key, ciphertext };
}

/**
 * Decrypts a ciphertext encrypted using OTP.
 * Takes key and ciphertext, returns original message as buffer or string.
 */
function decryptOTP({ key, ciphertext, returnType }) {
  if (key.length !== ciphertext.length) {
    throw new Error("The length of the key must match the length of the ciphertext.");
  }

  let p = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) {
    p[i] = key[i] ^ ciphertext[i];
  }

  if (!returnType || returnType === 'buffer') {
    return p;
  } else if (returnType === 'string') {
    return p.toString();
  } else {
    throw new Error(`${returnType} is not supported as a return type`);
  }
}

/**
 * Generates a globally unique identifier (GUID).
 */
function makeGUID() {
  return crypto.randomBytes(48).toString('hex');
}

/**
 * Hashes a given string using SHA-256 and returns the hash in hexadecimal format.
 */
function hash(s) {
  s = s.toString();
  return crypto.createHash(HASH_ALG).update(s).digest('hex');
}

/**
 * Returns a random byte between 0 and 255.
 */
function sample() {
  return crypto.randomBytes(1).readUInt8();
}

/**
 * Generates a uniform random integer between 0 and (range - 1).
 * Uses rejection sampling to ensure uniformity.
 */
function randInt(range) {
  if (range > MAX_RANGE) {
    throw new Error(`Range cannot be more than ${MAX_RANGE}`);
  }

  let q = Math.floor(MAX_RANGE / range);
  let max = q * range;

  let n;
  do {
    n = sample();
  } while (n >= max);

  return n % range;
}

// Exporting all utility functions
module.exports = {
  makeOTP,
  decryptOTP,
  makeGUID,
  hash,
  randInt,
  sample,
};

// Optional CLI to test OTP encryption/decryption
if (require.main === module) {
  const input = "Hello from CLI!";
  console.log(`Original message: ${input}`);

  const { key, ciphertext } = makeOTP({ string: input });
  console.log(`Encrypted (hex): ${ciphertext.toString('hex')}`);
  console.log(`Key        (hex): ${key.toString('hex')}`);

  const output = decryptOTP({ key, ciphertext, returnType: 'string' });
  console.log(`Decrypted message: ${output}`);
}
