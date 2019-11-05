'use strict';

const crypto = require('crypto');

const SALT_BYTE_SIZE = 24;
const HASH_BYTE_SIZE = 18;
const PBKDF2_ITERATIONS = 64000;
const PBKDF2_ALGORITHM = "sha1";

// These constants define the encoding and may not be changed.
const HASH_SECTIONS = 5;
const HASH_ALGORITHM_INDEX = 0;
const ITERATION_INDEX = 1;
const HASH_SIZE_INDEX = 2;
const SALT_INDEX = 3;
const PBKDF2_INDEX = 4;

class InvalidHashException extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidHashException";
  }
}
class CannotPerformOperationException extends Error {
  constructor(message) {
    super(message);
    this.name = "CannotPerformOperationException";
  }
}

function slowEqual (aArray, bArray) {
  let diff = aArray.length ^ bArray.length;
  for (let i = 0; i < aArray.length && i < bArray.length; i++) {
    diff |= aArray[i] ^ bArray[i];
  }
  return diff === 0;
}

function createHash(password) {
  const salt = crypto.randomBytes(SALT_BYTE_SIZE);
  const hash = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
  return `sha1:${PBKDF2_ITERATIONS}:${hash.length}:${toBase64(salt)}:${toBase64(hash)}`;
}

function verifyPassword(password, correctHash) {
  const params = correctHash.split(":");
  if (params.length !== HASH_SECTIONS) {
    throw new InvalidHashException("Fields are missing from the password hash.");
  }

  if (params[HASH_ALGORITHM_INDEX] !== "sha1") {
    throw new CannotPerformOperationException("Unsupported hash type.");
  }

  const iterations = parseInt(params[ITERATION_INDEX]);
  if (isNaN(iterations) || iterations < 1) {
    throw new InvalidHashException(`Invalid number of iterations: ${params[ITERATION_INDEX]}`);
  }


  const saltBuffer = fromBase64(params[SALT_INDEX]);
  const hashBuffer = fromBase64(params[PBKDF2_INDEX]);
  const storedHashSize = parseInt(params[HASH_SIZE_INDEX]);
  if (isNaN(storedHashSize)) {
    throw new InvalidHashException(`Could not parse the hash size as an integer: ${params[HASH_SIZE_INDEX]}`);
  }

  if (storedHashSize !== hashBuffer.length) {
    throw new InvalidHashException("Hash length doesn't match stored hash length.");
  }

  const generateHash = pbkdf2(password, saltBuffer, iterations, hashBuffer.length);
  return slowEqual(hashBuffer, generateHash);
}

function pbkdf2(password, salt, iterations, bytes) {
  try {
    return crypto.pbkdf2Sync(password, salt, iterations, bytes, PBKDF2_ALGORITHM);
  } catch (error) {
    throw new CannotPerformOperationException("Hash algorithm not supported.", error);
  }
}

function fromBase64(base64Str) {
  return Buffer.from(base64Str, 'base64')
}

function toBase64(buffer) {
  return buffer.toString('base64');
}


module.exports = {
    createHash,
    verifyPassword,
    InvalidHashException,
    CannotPerformOperationException,
}

