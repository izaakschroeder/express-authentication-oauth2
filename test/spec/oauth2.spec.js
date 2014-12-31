
'use strict';

var oauth2 = require('oauth2'),
	express = require('express'),
	request = require('supertest');

describe('oauth2', function() {

	beforeEach(function() {
		this.app = express();
		this.agent = {
			get: sinon.stub().returnsThis(),
			set: sinon.stub().returnsThis(),
			parse: sinon.stub().returnsThis(),
			query: sinon.stub().returnsThis(),
			end: sinon.stub().callsArgWith(0, null, null)
		};
		this.app.set('trust proxy', true);
		this.app.use(function(req, res, next) {
			req.headers['x-forwarded-for'] = '127.0.0.1';
			next();
		});
	});

	it('should create middleware', function() {
		oauth2({
			tokenUrl: 'https://test/token',
			authorizeUrl: 'https://test/token',
			clientId: 'abc',
			clientSecret: 'def'
		});
	});

	it('should map `endpoint` to `tokenUrl` and `authorizeUrl`', function() {
		oauth2({
			endpoint: 'https://test/',
			clientId: 'abc',
			clientSecret: 'def'
		});
	});

	it('should fail with no options', function() {
		expect(oauth2).to.throw(TypeError);
	});

	it('should fail without `tokenUrl`', function() {
		expect(function() {
			oauth2({
				authorizeUrl: 'https://test/token',
				clientId: 'abc',
				clientSecret: 'def'
			});
		}).to.throw(TypeError);
	});

	it('should fail without `authorizeUrl`', function() {
		expect(function() {
			oauth2({
				tokenUrl: 'https://test/token',
				clientId: 'abc',
				clientSecret: 'def'
			});
		}).to.throw(TypeError);
	});

	it('should fail without `clientId`', function() {
		expect(function() {
			oauth2({
				tokenUrl: 'https://test/token',
				authorizeUrl: 'https://test/token',
				clientSecret: 'def'
			});
		}).to.throw(TypeError);
	});

	it('should fail without `clientSecret`', function() {
		expect(function() {
			oauth2({
				tokenUrl: 'https://test/token',
				authorizeUrl: 'https://test/token',
				clientId: 'abc'
			});
		}).to.throw(TypeError);
	});

	it('should build scopes correctly', function() {
		oauth2({
			endpoint: 'https://test/',
			clientId: 'abc',
			clientSecret: 'def',
			scope: [ 'a', 'b' ]
		});

	});

	it('should redirect to self by default', function(done) {
		this.app.use(oauth2({
			tokenUrl: 'https://test/token',
			authorizeUrl: 'https://test/token',
			clientId: 'abc',
			clientSecret: 'def',
			state: false,
			agent: this.agent
		}));
		this.agent.end.callsArgWith(0, null, null);
		request(this.app)
			.get('/')
			.query({
				code: 'potato'
			})
			.expect(function(res) {
				expect(res).to.have.property('statusCode', 302);
				expect(res.headers).to.have.property('location');
				expect(res.headers.location)
					.to.match(/redirect_uri=http.*127.0.0.1/);
			})
			.end(done);
	});

	it('should work with array of scopes', function(done) {
		this.app.use(oauth2({
			tokenUrl: 'https://test/token',
			authorizeUrl: 'https://test/token',
			clientId: 'abc',
			clientSecret: 'def',
			state: false,
			redirect: 'http://test/landing',
			agent: this.agent,
			scope: [ 'a', 'b', 'c' ]
		}));
		this.agent.end.callsArgWith(0, null, null);
		request(this.app)
			.get('/')
			.query({
				code: 'potato'
			})
			.expect(function(res) {
				expect(res).to.have.property('statusCode', 302);
				expect(res.headers).to.have.property('location');
				expect(/scope=([^&$]*[abc]){3}/.test(res.headers.location))
					.to.be.true;
			})
			.end(done);
	});

	it('should disable state checking if desired', function(done) {
		this.app.use(oauth2({
			tokenUrl: 'https://test/token',
			authorizeUrl: 'https://test/token',
			clientId: 'abc',
			clientSecret: 'def',
			state: false,
			agent: this.agent
		}));
		this.agent.end.callsArgWith(0, null, {
			body: {
				/*eslint-disable camelcase*/
				access_code: 'foo'
				/*eslint-enable camelcase*/
			}
		});
		request(this.app)
			.get('/')
			.query({
				code: 'potato',
				state: 'foo'
			})
			.expect(function(res) {
				expect(res).to.have.property('statusCode', 502);
			})
			.end(done);
	});

	describe('during request processing', function() {

		beforeEach(function() {

			this.middleware = oauth2({
				tokenUrl: 'https://test/token',
				authorizeUrl: 'https://test/token',
				clientId: 'abc',
				clientSecret: 'def',
				state: {
					key: '1234567890'
				},
				redirect: 'http://test/landing',
				agent: this.agent
			});

			this.app.use(this.middleware);
			this.app.get('/', function(req, res) {
				res.status(200).send(req.authentication);
			});
			this.state = {
				rid: '127.0.0.1',
				exp: Math.floor((Date.now() / 1000) + 7000),
				rfp: 0,
				/*eslint-disable camelcase*/
				target_uri: 'http://test/landing'
				/*eslint-enable camelcase*/
			};
		});



		it('should redirect when `query.state` is not present', function(done) {
			request(this.app)
				.get('/')
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 302);
				})
				.end(done);
		});

		it('should fail on with `state` but no `code`', function(done) {
			request(this.app)
				.get('/?state=poop')
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 400);
				})
				.end(done);
		});

		it('should fail on with invalid `state`', function(done) {
			request(this.app)
				.get('/?state=poop&code=poop')
				.expect(function(res) {
					expect(res.body)
						.to.have.property('error', 'INVALID_STATE');
				})
				.end(done);
		});

		it('should fail on expired `state.expires`', function(done) {
			this.state.exp = Math.floor((Date.now() / 1000) - 7000);
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res.body)
						.to.have.property('error', 'INVALID_STATE');
				})
				.end(done);
		});

		it('should fail on `state.rid` mismatch', function(done) {
			this.state.rid = '127.0.0.2';
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res.body)
						.to.have.property('error', 'INVALID_STATE');
				})
				.end(done);
		});

		it('should fail on `state.rfp` mismatch', function(done) {
			this.state.rfp = 1;
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res.body)
						.to.have.property('error', 'INVALID_STATE');
				})
				.end(done);
		});

		it('should fail on `state.target_uri` mismatch', function(done) {
			/*eslint-disable camelcase*/
			this.state.target_uri = 'http://www.derp.com';
			/*eslint-enable camelcase*/
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res.body)
						.to.have.property('error', 'INVALID_STATE');
				})
				.end(done);
		});

		it('should fail with malformed response', function(done) {
			this.agent.end.callsArgWith(0, null, { body: null });
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 502);
				})
				.end(done);
		});

		it('should fail if `request` fails', function(done) {
			this.agent.end.callsArgWith(0, 'fake-error');
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 502);
				})
				.end(done);
		});

		it('should fail with invalid properties', function(done) {
			this.agent.end.callsArgWith(0, null, { body: { foo: 'bar' } });
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 502);
				})
				.end(done);
		});

		it('should deny when `error` is present', function(done) {
			this.agent.end.callsArgWith(0, null, {
				body: { error: 'foo' }
			});
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res.body)
						.to.have.property('error', 'foo');
				})
				.end(done);
		});

		it('should succeed when `access_token` is present', function(done) {
			/*eslint-disable camelcase*/
			this.agent.end.callsArgWith(0, null, {
				body: { access_token: 'foo' }
			});
			/*eslint-enable camelcase*/
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 200);
					expect(res.body).to.have.property('token', 'foo');
				})
				.end(done);
		});

		it('should make correct `expires` using `expires`', function(done) {
			this.agent.end.callsArgWith(0, null, {
				body: {
					/*eslint-disable camelcase*/
					access_token: 'foo',
					/*eslint-enable camelcase*/
					expires: Math.floor(Date.now() / 1000)
				}
			});
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 200);
					expect(res.body).to.have.property('expires');
				})
				.end(done);
		});

		it('should make correct `expires` using `expires_in`', function(done) {
			this.agent.end.callsArgWith(0, null, {
				body: {
					/*eslint-disable camelcase*/
					access_token: 'foo',
					expires_in: 3600
					/*eslint-enable camelcase*/
				}
			});
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 200);
					expect(res.body).to.have.property('expires');
				})
				.end(done);
		});

		it('should make correct `expires` using `expires_at`', function(done) {
			this.agent.end.callsArgWith(0, null, {
				body: {
					/*eslint-disable camelcase*/
					access_token: 'foo',
					expires_at: Math.floor(Date.now() / 1000)
					/*eslint-enable camelcase*/
				}
			});
			request(this.app)
				.get('/')
				.query({ state:
					this.middleware.state(this.state),
					code: 'potato'
				})
				.expect(function(res) {
					expect(res).to.have.property('statusCode', 200);
					expect(res.body).to.have.property('expires');
				})
				.end(done);
		});
	});
});
