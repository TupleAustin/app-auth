'use strict';

var jwt = require('jsonwebtoken');
var uuid = require('uuid-v4');
var fs = require('fs');
var policy = require('access-policy');

function sign(data, secret, expiration) {
  if (!data) {
    throw new SyntaxError('Signature data missing');
  }

  if (!uuid.isUUID(secret)) {
    throw new TypeError('Incorrect secret type, must be UUIDV4');
  }

  return jwt.sign(data, secret, {
    expiresIn: expiration || '30m'
  });
}

function verify(token, secret) {
  try {
    var decoded = jwt.verify(token, secret);
  } catch (err) {
    throw err;
  }

  return decoded;
}

function encode(statements, data) {
  try {
    var encoded = policy.encode(statements, data);
  } catch (err) {
    throw err;
  }

  return encoded;
}

function resource(statements, context) {
  try {
    var allowed = policy.resource(statements, context);
  } catch (err) {
    throw err;
  }

  return allowed;
}

function restriction(statements, context) {
  try {
    var allowed = policy.restriction(statements, context);
  } catch (err) {
    throw err;
  }

  return allowed;
}

module.exports = {
  sign: sign,
  verify: verify,
  encode: encode,
  test: resource,
  resource: resource,
  data: restriction
};

