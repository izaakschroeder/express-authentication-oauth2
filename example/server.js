
var path = require('path'),
	express = require('express'),
	authentication = require('express-authentication'),
	oauth = require(path.join(__dirname, '..'));

var app = express(),
	auth = authentication(),
	facebook = oauth({
		clientId: process.env['APP_ID'],
		clientSecret: process.env['APP_SECRET'],
		authorizeUrl: 'https://www.facebook.com/dialog/oauth',
		tokenUrl: 'https://graph.facebook.com/oauth/access_token'
	});


app.get('/', auth.for(facebook).required(), function(req, res) {
	var result = auth.for(facebook).of(req);
	res.status(200).send(result);
});

app.listen(process.env['PORT']);
