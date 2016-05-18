'use strict';

var assert = require('assert');
var jwt = require('jsonwebtoken');
var auth = require('../index');

var secret = 'ae333df7-3dc4-4c3f-bdcf-a6220a8529ae'
function data() {
  return {
    id: 'ddff64c5-1c16-4aaf-9d1b-07f2552831b1'
  };
}

describe('Signing', function () {
  describe('with missing argument', function () {
    it('should throw a syntax error', function () {
      assert.throws(auth.sign, SyntaxError);
      assert.throws(auth.sign, /SyntaxError: Signature data missing/);
    });
  });

  describe('with incorrect secret format', function () {
    it('should throw a type error', function () {
      function actual() {
        auth.sign({}, '12345');
      }

      assert.throws(actual, TypeError);
      assert.throws(actual, /TypeError: Incorrect secret type/);
    });
  });

  describe('with data and valid secret', function () {
    it('should return a token', function () {
      var token = auth.sign(data(), secret);
      assert.ok(token);
    });

    it('should contain an id', function () {
      var token = auth.sign(data(), secret);
      var decoded = jwt.decode(token);

      assert.equal(decoded.id, data().id);
    });

    it('should expire in 30 minutes', function () {
      var token = auth.sign(data(), secret);
      var decoded = jwt.decode(token)
      var expected = 1800000;
      var actual = (decoded.exp - decoded.iat) * 1000;

      assert.strictEqual(actual, expected);
    });

    it('should expire in 5 minutes', function () {
      var token = auth.sign(data(), secret, '5m');
      var decoded = jwt.decode(token)
      var expected = 300000;
      var actual = (decoded.exp - decoded.iat) * 1000;

      assert.strictEqual(actual, expected);
    });
  });
});

describe('Verifying', function () {
  var token = auth.sign(data(), secret);

  it('should throw a jwt provided error', function () {
    assert.throws(auth.verify, /JsonWebTokenError: jwt must be provided/);
  });

  it('should throw a jwt malformed error', function () {
    assert.throws(auth.verify.bind(null, token.slice(-1)), /JsonWebTokenError: jwt malformed/);
  });

  it('should throw a secret key error', function () {
    assert.throws(auth.verify.bind(null, token), /JsonWebTokenError: secret or public key must be provided/);
  });

  it('should return a verified token', function () {
    var decoded = auth.verify(token, secret);
    assert.ok(decoded);
    assert.equal(decoded.id, data().id);
  });
});

describe('Encoding statements', function () {
  var statements = [{
    action: 'GET',
    resource: '/user/${id}'
  }];

  it('should throw a SyntaxError', function () {
    assert.throws(auth.encode, SyntaxError);
    assert.throws(auth.encode, /SyntaxError: Must include statements to encode/);
  });

  it('should return an encoded statement', function () {
    var encoded = auth.encode(statements, data());
    assert.notDeepEqual(statements, encoded);
    assert.equal(statements[0].action, encoded[0].action);
    assert.equal('/user/ddff64c5-1c16-4aaf-9d1b-07f2552831b1', encoded[0].resource);
  });
});

describe('Testing statements', function () {
  var statements = [{
    action: 'GET',
    resource: '/user/${id}'
  }];

  it('should throw an error', function () {
    assert.throws(auth.test, TypeError);
  });

  it('should return an array with 1 statement', function () {
    var localData = {
      id: 'ddff64c5-1c16-4aaf-9d1b-07f2552831b1',
      Action: 'GET',
      Resource: '/user/ddff64c5-1c16-4aaf-9d1b-07f2552831b1'
    };

    var allowed = auth.test(statements, localData);
    assert.equal(allowed.length, 1);
  });

  it('should return false', function () {
    var localData = {
      id: "ddff64c5-1c16-4aaf-9d1b-07f2552831b1",
      Action: 'GET',
      Resource: '/user'
    };

    var allowed = auth.test(statements, localData);
    assert.strictEqual(allowed, false);
  });
});

describe('Testing restirctions', function () {
  var statements = [{
    action: 'GET',
    resource: '/user',
    restriction: {
      equals: {
        user_id: 'ddff64c5-1c16-4aaf-9d1b-07f2552831b1'
      }
    }
  }];

  it('should return true', function () {
    var localResource = {
      Action: 'GET',
      Resource: '/user'
    };

    var localData = {
      name: 'bob',
      user_id: 'ddff64c5-1c16-4aaf-9d1b-07f2552831b1'
    };

    var passed = auth.resource(statements, localResource);
    var allowed = auth.data(passed, localData);

    assert.strictEqual(allowed, true);
  });

  it('should return false', function () {
    var localResource = {
      Action: 'GET',
      Resource: '/user'
    };

    var localData = {
      name: 'bob',
      user_id: 'ddff64c5-1c16-4aaf-9d1b-07f2552831b'
    };

    var passed = auth.resource(statements, localResource);
    var allowed = auth.data(passed, localData);

    assert.strictEqual(allowed, false);
  });
});

