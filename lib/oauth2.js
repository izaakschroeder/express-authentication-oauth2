
'use strict';

var _ = require('lodash'),
	url = require('url'),
	request = require('superagent'),
	jwt = require('jwt-simple'),
	crypto = require('crypto');

// http://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-00


function selfUrl(req) {
	return req.protocol +
		'://' + req.headers['host'] +
		req._parsedUrl.pathname ;
}

function urlify(entry) {
	if (_.isString(entry)) {
		entry = url.parse(entry);
	}
	if (!_.isObject(entry)) {
		throw new TypeError();
	}
	return entry;
}

module.exports = function oauth2(options) {

	if (!_.isObject(options)) {
		throw new TypeError('No `options` provided.');
	} else if (!options.clientId) {
		throw new TypeError('No `options.clientId` provided.');
	} else if (!options.clientSecret) {
		throw new TypeError('No `options.clientSecret` provided.');
	}

	// turn urls into options
	options = _.merge({
		agent: request,
		state: {
			expires: 60000,
			key: crypto.randomBytes(128),
			signer: 'express-authentication-oauth2'
		},
		scope: null
	}, options);

	// sane defaults
	if (options.endpoint) {
		options.authorizeUrl = options.endpoint + '/oauth/authorize';
		options.tokenUrl = options.endpoint + '/oauth/token';
	}

	options.authorizeUrl = urlify(options.authorizeUrl);
	options.tokenUrl = urlify(options.tokenUrl);

	function getRfp() {
		return 0;
	}

	// TODO: Figure out best way to include RFP value; candidates
	// include: automatic generation via cookies, use of some CSRF
	// library/token, export a callback via the options object.
	// IP verification presently should be enough to mitigate a large
	// number of CSRF attacks on this endpoint for now.
	function buildState(params) {

		var now = Math.floor(Date.now() / 1000),
			exp = now + Math.floor(options.expires / 1000);

		return jwt.encode(_.assign({
			aud: options.clientId,
			kid: options.state.signer,
			iat: now,
			exp: now + exp
		}, params), options.state.key);
	}

	function expires(data) {
		if (_.has(data, 'expires_in')) {
			return new Date(Date.now() + parseInt(data.expires_in, 10) * 1000);
		} else if (_.has(data, 'expires_at')) {
			return new Date(parseInt(data.expires_at, 10) * 1000);
		} else if (_.has(data, 'expires')) {
			return new Date(parseInt(data.expires, 10) * 1000);
		} else {
			return null;
		}
	}

	function verifyState(state, against) {

		state = jwt.decode(state, options.state.key);

		if (Date.now() > state.exp * 1000) {
			throw new Error({
				status: 400,
				error: 'INVALID_STATE',
				reason: 'STATE_EXPIRED'
			});
		} else if (state.rid !== against.ip) {
			throw new Error({
				status: 400,
				error: 'INVALID_STATE',
				reason: 'IP_ADDRESS_MISMATCH',
				expected: state.rid
			});
		} else if (state.rfp !== against.rfp) {
			throw new Error({
				status: 400,
				error: 'INVALID_STATE',
				reason: 'RFP_MISMATCH',
				expected: state.rfp
			});
		} else if (state.target_uri !== against.redirect) {
			throw new Error({
				status: 400,
				error: 'INVALID_STATE',
				reason: 'URI_MISMATCH'
			});
		}
	}

	function middleware(req, res, next) {

		var redirect = options.redirect || selfUrl(req);

		if (!req.query.state) {
			/*eslint-disable camelcase*/
			var destination = url.format(_.merge({ }, options.authorizeUrl, {
				search: null,
				query: {
					client_id: options.clientId,
					redirect_uri: redirect,
					state: options.state ? buildState({
						rfp: getRfp(req),
						rid: req.ip,
						target_uri: redirect
					}) : '',
					response_type: 'code',
					scope: _.isArray(options.scope) ?
						options.scope.join(' ') : options.scope
				}
			}));
			/*eslint-enable camelcase*/

			res.redirect(302, destination);

		} else if (req.query.code) {

			req.challenge = req.query.code;
			if (options.state) {
				try {
					verifyState(req.query.state, {
						rfp: getRfp(req),
						ip: req.ip,
						redirect: redirect
					});
				} catch(e) {
					req.authenticated = false;
					req.authentication = {
						error: 'INVALID_STATE',
						reason: e
					};
					return next();
				}
			}

			options.agent
				.get(options.tokenUrl)
				.set('Accept', 'application/x-www-form-urlencoded')
				// Since even with "Accept: application/x-www-form-urlencoded"
				// Facebook loves to return text/plain... why? Who knows.
				.parse(request.parse['application/x-www-form-urlencoded'])
				.query({
					/*eslint-disable camelcase*/
					client_id: options.clientId,
					redirect_uri: redirect,
					client_secret: options.clientSecret,
					/*eslint-enable camelcase*/
					code: req.query.code
				})
				.end(function responded(err, upstream) {
					if (err) {
						return next({
							status: 502,
							error: 'INVALID_UPSTREAM',
							reason: err
						});
					} else if (!upstream.body) {
						next({ status: 502, error: 'INVALID_UPSTREAM' });
					} else if (_.has(upstream.body, 'error')) {
						req.authenticated = false;
						req.authentication = {
							error: upstream.body.error,
							description: upstream.body.error_description
						};
						next();
					} else if (_.has(upstream.body, 'access_token')) {
						req.authenticated = true;
						req.authentication = {
							token: upstream.body.access_token,
							expires: expires(upstream.body)
						};
						next();
					} else {
						next({ status: 502, error: 'INVALID_UPSTREAM' });
					}
				});
		} else {
			next({
				status: 400,
				error: 'NO_CODE',
				message: req.query.error
			});
		}
	}

	return _.assign(middleware, {
		state: buildState
	});
};
