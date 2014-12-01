

// appId, appSecret, scope
// "https://www.facebook.com/dialog/oauth?"
// 'https://graph.facebook.com/oauth/access_token?'


var crypto = require('crypto');

// http://tools.ietf.org/html/draft-bradley-oauth-jwt-encoded-state-00

/*
BASE64URL(UTF8(JWE Protected Header))
JWE Shared Unprotected Header
JWE Per-Recipient Unprotected Header
BASE64URL(JWE Encrypted Key)
BASE64URL(JWE Initialization Vector)
BASE64URL(JWE Ciphertext)
BASE64URL(JWE Authentication Tag)
BASE64URL(JWE AAD)
*/

var jwt = require('jwt-simple');

function encrypt() {

}

function decrypt() {

}

function readState() {

}

function writeState() {

}

module.exports = function(options) {
	var nonces = { };



	return function(req, res, next) {

		var nonce = req.query.state,
			url = req.protocol + '://' + req.headers['host'] + req._parsedUrl.pathname ;

		var redirect = (function() {

			crypto.randomBytes(function(err, random) {
				nonce = random.toString('hex');
				nonces[nonce] = setTimeout((function(nonce) {
					delete nonces[nonce];
				}), 1000*3600)

				res.redirect(302, options.loginUrl + '?' + querystring.stringify({
					client_id: options.clientId,
					redirect_uri: url,
					state: nonce,
					response_type: 'code',
					scope: scope.join(',')
				}));
			});
		});

		if (!nonce || typeof nonces[nonce] === "undefined")
			return redirect();

		clearTimeout(nonces[nonce]);
		delete nonces[nonce];

		if (req.query.code) {
			request.get(options.tokenUrl + '?' + querystring.stringify({
				client_id: appId,
				redirect_uri: url,
				client_secret: options.clientSecret,
				code: req.query.code
			}), function(err, data) {
				var result

				if (err) {
					return next(err);
				} else if (!(result = querystring.parse(data))) {
					return next({ error: 'RESPONSE_INVALID' });
				} else {
					req.authenicated = true;
					req.authenication = req.query.code;
					next();
				}
			});
		}
		else {
			next({ error: 'NO_CODE', message: parts.query.error});
		}
	};
};
