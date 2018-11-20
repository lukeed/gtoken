/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

const test = require('tape');
const { readFileSync } = require('fs');
const { GoogleToken } = require('../dist/gtoken');
const nock = require('nock');

const EMAIL = 'example@developer.gserviceaccount.com';
const KEYCONTENTS = readFileSync('./test/assets/key.pem', 'utf8');
const KEYJSONCONTENTS = readFileSync('./test/assets/key.json', 'utf8');
const GOOGLE_TOKEN_URLS = ['https://www.googleapis.com', '/oauth2/v4/token'];
const GOOGLE_REVOKE_TOKEN_URLS = ['https://accounts.google.com', '/o/oauth2/revoke', '?token='];

const TESTDATA = {
	email: 'email@developer.gserviceaccount.com',
	scope: 'scope123',
	key: KEYCONTENTS
};

nock.disableNetConnect();

test('exports', t => {
	t.is(typeof GoogleToken, 'function');
	t.end();
});

test('initialize without options', t => {
	t.ok(new GoogleToken);
	t.end();
});

test('.iss :: email', t => {
	let gtoken = new GoogleToken({ email:EMAIL });
	t.is(gtoken.email, undefined);
	t.is(gtoken.iss, EMAIL);
	t.end();
});

test('.iss :: iss', t => {
	let gtoken = new GoogleToken({ iss:EMAIL });
	t.is(gtoken.iss, EMAIL);
	t.end();
});

test('.iss :: sub', t => {
	let gtoken = new GoogleToken({ sub:EMAIL });
	t.is(gtoken.sub, EMAIL);
	t.end();
});

test('.iss :: email > iss', t => {
	let gtoken = new GoogleToken({ iss:EMAIL, email:'foobar' });
	t.is(gtoken.iss, 'foobar');
	t.end();
});

test('.scope :: string', t => {
	let gtoken = new GoogleToken({ scope:'hello world' });
	t.is(gtoken.scope, 'hello world');
	t.end();
});

test('.scope :: array of strings', t => {
	let gtoken = new GoogleToken({ scope:['hello', 'world'] });
	t.is(gtoken.scope, 'hello world');
	t.end();
});

test('isExpired()', t => {
	let gtoken = new GoogleToken();
	t.is(typeof gtoken.isExpired, 'function');

	t.true(gtoken.isExpired(), 'should be expired without token');

	gtoken.token = 'hello';
	t.true(gtoken.isExpired(), 'should be expired without expires_at');

	gtoken.expiresAt = Date.now() + 10000;
	t.false(gtoken.isExpired(), 'shouldnt be expired with future date');

	gtoken.expiresAt = Date.now() - 10000;
	t.true(gtoken.isExpired(), 'should be expired with past date');

	gtoken.token = null;
	gtoken.expiresAt = Date.now() + 10000;
	t.true(gtoken.isExpired(), 'should be expired with no token');

	t.end();
});

// test('.revokeToken()', async t => {
// 	t.plan(2);

// 	let gtoken = new GoogleToken();
// 	t.is(typeof gtoken.revokeToken, 'function', '~> is a function');

// 	let token = 'w00t';
// 	let scope = createRevokeMock(token);
// 	gtoken.token = token;

// 	await gtoken.revokeToken();
// 	t.is(gtoken.token, null);

// 	scope.done();
// });

// 	it('should return appropriate error with HTTP 404s', done => {
// 		const token = 'w00t';
// 		const scope = createRevokeMock(token, 404);
// 		const gtoken = new GoogleToken();
// 		gtoken.token = token;
// 		gtoken.revokeToken(err => {
// 			assert(err);
// 			scope.done();
// 			done();
// 		});
// 	});

// 	it('should run accept config properties with async', async () => {
// 		const token = 'w00t';
// 		const scope = createRevokeMock(token);

// 		const gtoken = new GoogleToken();
// 		gtoken.token = token;
// 		await gtoken.revokeToken();
// 		assert.strictEqual(gtoken.token, null);
// 		scope.done();
// 	});

// 	it('should return error when no token set', done => {
// 		const gtoken = new GoogleToken();
// 		gtoken.token = null;
// 		gtoken.revokeToken(err => {
// 			assert(err && err.message);
// 			done();
// 		});
// 	});

// 	it('should return error when no token set with async', async () => {
// 		const gtoken = new GoogleToken();
// 		gtoken.token = null;
// 		let err;
// 		try {
// 			await gtoken.revokeToken();
// 		} catch (e) {
// 			err = e;
// 		}
// 		assert(err && err.message);
// 	});
// });

test('getToken()', async t => {
	let gtoken = new GoogleToken();
	t.is(typeof gtoken.getToken, 'function');

	try {
		await gtoken.getToken();
	} catch (err) {
		t.pass('should error when key not set');
	}

	t.end()
});

// 	it('should accept additional claims', async () => {
// 		const opts = Object.assign(
// 				TESTDATA_KEYFILE, {additionalClaims: {fancyClaim: 'isFancy'}});
// 		const gtoken = new GoogleToken(opts);
// 		const scope = createGetTokenMock();
// 		const token = await gtoken.getToken();
// 		scope.done();
// 		assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
// 	});

// 	it('should return error if iss is not set with .json', done => {
// 		const gtoken = new GoogleToken(TESTDATA_KEYFILENOEMAILJSON);
// 		gtoken.getToken(err => {
// 			assert(err);
// 			if (err) {
// 				// assert.strictEqual(
// 				// 		(err as NodeJS.ErrnoException).code, 'MISSING_CREDENTIALS');
// 				done();
// 			}
// 		});
// 	});

// 	it('should return cached token if not expired', done => {
// 		const gtoken = new GoogleToken(TESTDATA);
// 		gtoken.token = 'mytoken';
// 		gtoken.expiresAt = Date.now() + 10000;
// 		gtoken.getToken((err, token) => {
// 			assert.strictEqual(token, 'mytoken');
// 			done();
// 		});
// 	});


// 	it('should return error if unknown file type is used', done => {
// 		const gtoken = new GoogleToken(TESTDATA_UNKNOWN);
// 		gtoken.getToken(err => {
// 			assert(err);
// 			if (err) {
// 				// assert.strictEqual(
// 				// 		(err as NodeJS.ErrnoException).code, 'UNKNOWN_CERTIFICATE_TYPE');
// 				done();
// 			}
// 		});
// 	});

// 	describe('request', () => {
// 		it('should be run with correct options', done => {
// 			const gtoken = new GoogleToken(TESTDATA);
// 			const fakeToken = 'nodeftw';
// 			const scope = createGetTokenMock(200, {'access_token': fakeToken});
// 			gtoken.getToken((err, token) => {
// 				scope.done();
// 				assert.strictEqual(err, null);
// 				assert.strictEqual(token, fakeToken);
// 				done();
// 			});
// 		});

// 		it('should set and return correct properties on success', done => {
// 			const gtoken = new GoogleToken(TESTDATA);
// 			const RESPBODY = {
// 				access_token: 'accesstoken123',
// 				expires_in: 3600,
// 				token_type: 'Bearer'
// 			};
// 			const scope = createGetTokenMock(200, RESPBODY);
// 			gtoken.getToken((err, token) => {
// 				scope.done();
// 				assert.deepStrictEqual(gtoken.rawToken, RESPBODY);
// 				assert.strictEqual(gtoken.token, 'accesstoken123');
// 				assert.strictEqual(gtoken.token, token);
// 				assert.strictEqual(err, null);
// 				assert(gtoken.expiresAt);
// 				if (gtoken.expiresAt) {
// 					assert(gtoken.expiresAt >= Date.now());
// 					assert(gtoken.expiresAt <= (Date.now() + (3600 * 1000)));
// 				}
// 				done();
// 			});
// 		});

// 		it('should set and return correct properties on error', done => {
// 			const ERROR = 'An error occurred.';
// 			const gtoken = new GoogleToken(TESTDATA);
// 			const scope = createGetTokenMock(500, {error: ERROR});
// 			gtoken.getToken((err, token) => {
// 				scope.done();
// 				assert(err);
// 				assert.strictEqual(gtoken.rawToken, null);
// 				assert.strictEqual(gtoken.token, null);
// 				if (err) assert.strictEqual(err.message, ERROR);
// 				assert.strictEqual(gtoken.expiresAt, null);
// 				done();
// 			});
// 		});

// 		it('should include error_description from remote error', done => {
// 			const gtoken = new GoogleToken(TESTDATA);
// 			const ERROR = 'error_name';
// 			const DESCRIPTION = 'more detailed message';
// 			const RESPBODY = {error: ERROR, error_description: DESCRIPTION};
// 			const scope = createGetTokenMock(500, RESPBODY);
// 			gtoken.getToken((err, token) => {
// 				scope.done();
// 				assert(err instanceof Error);
// 				if (err) {
// 					assert.strictEqual(err.message, ERROR + ': ' + DESCRIPTION);
// 					done();
// 				}
// 			});
// 		});

// 		it('should provide an appropriate error for a 404', done => {
// 			const gtoken = new GoogleToken(TESTDATA);
// 			const message = 'Request failed with status code 404';
// 			const scope = createGetTokenMock(404);
// 			gtoken.getToken((err, token) => {
// 				scope.done();
// 				assert(err instanceof Error);
// 				if (err) assert.strictEqual(err.message, message);
// 				done();
// 			});
// 		});
// 	});
// });

function createGetTokenMock(code=200, body) {
	return nock(GOOGLE_TOKEN_URLS[0])
		.replyContentLength()
		.post(
				GOOGLE_TOKEN_URLS[1],
				{
					grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
					assertion: /.?/
				},
				{
					reqheaders: {'Content-Type': 'application/x-www-form-urlencoded'}
				}
		).reply(code, body || {});
}

function createRevokeMock(token, code=200) {
	return nock(GOOGLE_REVOKE_TOKEN_URLS[0])
		.get(GOOGLE_REVOKE_TOKEN_URLS[1])
		.query({ token })
		.reply(code);
}
