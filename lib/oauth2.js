

var _ = require('lodash');
var crypto = require('crypto');

var url = require('url');

var request = require('superagent');

// http://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-00

/*

var jwt = require('jwt-simple');


*/

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


module.exports = function(options) {

	if (!_.isObject(options)) {
		throw new TypeError();
	} else if (!options.clientId) {
		throw new TypeError();
	} else if (!options.clientSecret) {
		throw new TypeError();
	}

	options = _.assign({ }, options);

	// sane defaults
	if (options.endpoint) {
		options.authorizeUrl = options.endpoint + '/oauth/authorize';
		options.tokenUrl = options.endpoint + '/oauth/token';
	}

	// turn urls into options
	_.assign(options, {
		authorizeUrl: urlify(options.authorizeUrl),
		tokenUrl: urlify(options.tokenUrl),
		state: {
			expires: 60000,
			key: crypto.randomBytes(128),
			signer: ''
		}
	});

	function authorizing(scopes) {

	}


	var fn = function middleware(req, res, next) {

		if (!req.query.state) {

			res.redirect(302, url.format(_.assign({ }, options.authorizeUrl, {
				search: null,
				query: _.assign({ }, options.authorizeUrl.query, {
					client_id: options.clientId,
					redirect_uri: selfUrl(req),
					state: jwt.encode({
						rfp: xx,
						kid: options.state.signer,
						iat: Date.now()
					}, options.state.key),
					response_type: 'code',
					scope: ''//scope.join(',')
				})
			})));

		} else if (req.query.code) {

			var state = null;
			req.challenge = req.query.code;

			try {
				state = jwt.decode(req.query.state, options.state.key);
			} catch (error) {
				return next({
					status: 400,
					error: 'INVALID_STATE',
					data: error
				});
			}

			var age = Date.now() - state.iat,
				remaining = options.state.expires - age;

			if (remaining <= 0) {
				return next({
					status: 400,
					error: 'INVALID_STATE',
					reason: 'STATE_EXPIRED',
					age: age,
					remaining: remaining
				});
			} else if (options.state.id && state.kid !== options.state.id) {
				return next({
					status: 400,
					error: 'INVALID_STATE',
					reason: 'KEY_ID_MISMATCH',
					given: state.kid,
					expected: options.state.id
				});
			} else if (state.rfp !== xxx) {
				return next({
					status: 400,
					error: 'INVALID_STATE',
					reason: 'INVALID_REQUEST_FORGERY_TOKEN'
				});
			}

			request
				.get(options.tokenUrl)
				.set('Accept', 'application/x-www-form-urlencoded')
				// Since even with "Accept: application/x-www-form-urlencoded"
				// Facebook loves to return text/plain... why? Who knows.
				.parse(request.parse['application/x-www-form-urlencoded'])
			 	.query({
					client_id: options.clientId,
					redirect_uri: selfUrl(req),
					client_secret: options.clientSecret,
					code: req.query.code
				})
				.end(function(err, res) {
					if (err) {
						return next(err);
					} else {
						req.authenticated = true;
						req.authentication = {
							token: res.body.access_token,
							expires: new Date(res.body.expires)
						};
						next();
					}
				});
		}
		else {
			next({
				statusCode: 400,
				error: 'NO_CODE',
				message: parts.query.error
			});
		}
	};

	return _.assign(fn, {
		authorizing: authorizing
	});
};
