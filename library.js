'use strict';

/*
		Welcome to the SSO OAuth plugin! If you're inspecting this code, you're probably looking to
		hook up NodeBB with your existing OAuth endpoint.

		Step 1: Fill in the "constants" section below with the requisite informaton. Either the "oauth"
				or "oauth2" section needs to be filled, depending on what you set "type" to.

		Step 2: Give it a whirl. If you see the congrats message, you're doing well so far!

		Step 3: Customise the `parseUserReturn` method to normalise your user route's data return into
				a format accepted by NodeBB. Instructions are provided there. (Line 146)

		Step 4: If all goes well, you'll be able to login/register via your OAuth endpoint credentials.
	*/

const User = require.main.require('./src/user');
const Groups = require.main.require('./src/groups');
const db = require.main.require('./src/database');
const authenticationController = require.main.require('./src/controllers/authentication');

const async = require('async');

const passport = require.main.require('passport');
const nconf = require.main.require('nconf');
const winston = require.main.require('winston');

/**
	 * REMEMBER
	 *   Never save your OAuth Key/Secret or OAuth2 ID/Secret pair in code! It could be published and leaked accidentally.
	 *   Save it into your config.json file instead:
	 *
	 *   {
	 *     ...
	 *     "oauth": {
	 *       "id": "someoauthid",
	 *       "secret": "youroauthsecret"
	 *     }
	 *     ...
	 *   }
	 *
	 *   ... or use environment variables instead:
	 *
	 *   `OAUTH__ID=someoauthid OAUTH__SECRET=youroauthsecret node app.js`
	 */

const constants = Object.freeze({
	type: 'oauth2', // Either 'oauth' or 'oauth2'
	name: 'plutonium', // Something unique to your OAuth provider in lowercase, like "github", or "nodebb"
	// oauth: {
	// 	requestTokenURL: '',
	// 	accessTokenURL: '',
	// 	userAuthorizationURL: '',
	// 	consumerKey: nconf.get('oauth:key'), // don't change this line
	// 	consumerSecret: nconf.get('oauth:secret'), // don't change this line
	// },
	oauth2: {
		authorizationURL: 'https://forum.plutonium.pw/oauth2/authorize',
		tokenURL: 'https://forum.plutonium.pw/oauth2/token',
		clientID: nconf.get('plutonium-oauth:id'), // don't change this line
		clientSecret: nconf.get('plutonium-oauth:secret'), // don't change this line
	},
	userRoute: 'https://forum.plutonium.pw/oauth2/@me', // This is the address to your app's "user profile" API endpoint (expects JSON)
	scope: "identify",
	icon: "fa-atom",
});

const OAuth = {};
let configOk = false;
let passportOAuth;
let opts;

if (!constants.name) {
	winston.error('[sso-oauth] Please specify a name for your OAuth provider (library.js:32)');
} else if (!constants.type || (constants.type !== 'oauth' && constants.type !== 'oauth2')) {
	winston.error('[sso-oauth] Please specify an OAuth strategy to utilise (library.js:31)');
} else if (!constants.userRoute) {
	winston.error('[sso-oauth] User Route required (library.js:31)');
} else {
	configOk = true;
	winston.info("[sso-oauth] Pluto SSO config pass");
}

OAuth.init = function (data, callback) {
	const hostHelpers = require.main.require('./src/routes/helpers');

	/*hostHelpers.setupAdminPageRoute(data.router, '/admin/plugins/sso-plutonium', (req, res) => {
		res.render('admin/plugins/sso-plutonium', {
			title: constants.name,
			baseUrl: nconf.get('url'),
		});
	});*/

	hostHelpers.setupPageRoute(data.router, '/deauth/plutonium', [data.middleware.requireUser], (req, res) => {
		res.render('deauth', {
			service: 'Plutonium',
		});
	});

	data.router.post('/deauth/plutonium', [data.middleware.requireUser, data.middleware.applyCSRF], (req, res, next) => {
		OAuth.deleteUserData({
			uid: req.user.uid,
		}, (err) => {
			if (err) {
				return next(err);
			}

			res.redirect(`${nconf.get('relative_path')}/me/edit`);
		});
	});


	callback()
};

OAuth.getAssociation = function (data, callback) {
	User.getUserField(data.uid, `${constants.name}Id`, (err, plutoID) => {
		if (err) {
			return callback(err, data);
		}
		winston.info("[sso-oauth][getAssociation] got plutoID " + plutoID);
		if (plutoID) {
			data.associations.push({
				associated: true,
				url: `https://forum.plutonium.pw/uid/${plutoID}`,
				deauthUrl: `${nconf.get('url')}/deauth/plutonium`,
				name: "Plutonium",
				icon: constants.icon,
			});
		} else {
			data.associations.push({
				associated: false,
				url: `${nconf.get('url')}/auth/plutonium`,
				name: "Plutonium",
				icon: constants.icon,
			});
		}

		callback(null, data);
	});
};

OAuth.getStrategy = function (strategies, callback) {
	winston.info("[Pluto-SSO][getStrategy] start");
	if (configOk) {
		passportOAuth = require('passport-oauth')[constants.type === 'oauth' ? 'OAuthStrategy' : 'OAuth2Strategy'];
		winston.info("[Pluto-SSO][getStrategy] configOK");
		// if (constants.type === 'oauth') {
		// 	// OAuth options
		// 	opts = constants.oauth;
		// 	opts.callbackURL = `${nconf.get('url')}/auth/${constants.name}/callback`;

		// 	passportOAuth.Strategy.prototype.userProfile = function (token, secret, params, done) {
		// 		// If your OAuth provider requires the access token to be sent in the query  parameters
		// 		// instead of the request headers, comment out the next line:
		// 		this._oauth._useAuthorizationHeaderForGET = true;

		// 		this._oauth.get(constants.userRoute, token, secret, (err, body/* , res */) => {
		// 			if (err) {
		// 				return done(err);
		// 			}

		// 			try {
		// 				const json = JSON.parse(body);
		// 				OAuth.parseUserReturn(json, (err, profile) => {
		// 					if (err) return done(err);
		// 					profile.provider = constants.name;

		// 					done(null, profile);
		// 				});
		// 			} catch (e) {
		// 				done(e);
		// 			}
		// 		});
		// 	};
		// } else 
		if (constants.type === 'oauth2') {
			// OAuth 2 options
			opts = constants.oauth2;
			opts.callbackURL = `${nconf.get('url')}/auth/${constants.name}/callback`;
			opts.response_type="code";

			passportOAuth.Strategy.prototype.userProfile = function (accessToken, done) {
				// If your OAuth provider requires the access token to be sent in the query  parameters
				// instead of the request headers, comment out the next line:
				this._oauth2._useAuthorizationHeaderForGET = true;

				this._oauth2.get(constants.userRoute, accessToken, (err, body/* , res */) => {
					if (err) {
						winston.error(`[Pluto-SSO][getStrategy] failed to oauth get "${constants.userRoute}" with accessToken "${accessToken}" error object is` + JSON.stringify(err, null, 4));
						return done(Error("Bad response from from plutonium.pw"));
					}

					try {
						const json = JSON.parse(body);
						OAuth.parseUserReturn(json, (err, profile) => {
							if (err) return done(err);
							profile.provider = constants.name;

							done(null, profile);
						});
					} catch (e) {
						done(e);
					}
				});
			};
		}
		winston.info("[Pluto-SSO][getStrategy] Checkpoint 1");
		opts.passReqToCallback = true;

		passport.use(constants.name, new passportOAuth(opts, async (req, token, secret, profile, done) => {
			const user = await OAuth.login({
				oAuthid: profile.id,
				handle: profile.displayName,
				//email: profile.emails[0].value,
				//isAdmin: profile.isAdmin,
			}, req);

			if(user == undefined) {
				return done(new Error("Plutonium SSO registration is disabled."));
			}
			else {
				authenticationController.onSuccessfulLogin(req, user.uid);
				done(null, user);
			}
		}));
		winston.info("[Pluto-SSO][getStrategy] Checkpoint 2");
		strategies.push({
			name: constants.name,
			url: `/auth/${constants.name}`,
			callbackURL: `/auth/${constants.name}/callback`,
			icon: constants.icon,
			scope: (constants.scope || '').split(','),
		});
		winston.info("[Pluto-SSO][getStrategy] Checkpoint 3");
		callback(null, strategies);
	} else {
		winston.error("[Pluto-SSO][getStrategy] OAuth Configuration is invalid");
		callback(new Error('OAuth Configuration is invalid'));
	}
};

OAuth.parseUserReturn = function (data, callback) {
	// Alter this section to include whatever data is necessary
	// NodeBB *requires* the following: id, displayName, emails.
	// Everything else is optional.

	// Find out what is available by uncommenting this line:
	// console.log(data);
	// winston.info("[Pluto-SSO][parseUserReturn] data " + JSON.stringify(data, null, 4));

	const profile = {};
	profile.id = data.user.id;
	profile.displayName = data.user.username;

	// Do you want to automatically make somebody an admin? This line might help you do that...
	// profile.isAdmin = data.isAdmin ? true : false;

	// Delete or comment out the next TWO (2) lines when you are ready to proceed
	//process.stdout.write('===\nAt this point, you\'ll need to customise the above section to id, displayName, and emails into the "profile" object.\n===');
	//winston.info("[Pluto-SSO][parseUserReturn] Congrats! So far so good -- please see server log for details " + JSON.stringify(data, null, 4));
	//return callback(Error('Congrats! So far so good -- please see server log for details'));

	// eslint-disable-next-line
		callback(null, profile);
};

OAuth.login = async (payload, req) => {

	//if user can be found with his plutonium id use it
	let uid = await OAuth.getUidByOAuthid(payload.oAuthid);
	if (uid !== null) {
		// Existing User
		return ({
			uid: uid,
		});
	}
	//winston.info("[sso-oauth][OAuth.login] " + JSON.stringify(req, null, 4));
	//if not check if a user is already logged in and link the accounts
	if (req.user && req.user.uid) {
		winston.info("[sso-oauth][OAuth.login] Could not find a user with Pluto ID " + payload.oAuthid + " but user " + req.user.uid + " is logged in; linking them now!");
		await db.setObjectField(`${constants.name}Id:uid`, payload.oAuthid, req.user.uid);
		await User.setUserField(req.user.uid, `${constants.name}Id`, payload.oAuthid);
		return ({
			uid: req.user.uid,
		});
	  }
	
	//Plutonium does not expose user email addresses so trying to use them as backup won't work
	return;

	// Check for user via email fallback
	// uid = await User.getUidByEmail(payload.email);
	// if (!uid) {
	// 	/**
	// 		 * The email retrieved from the user profile might not be trusted.
	// 		 * Only you would know — it's up to you to decide whether or not to:
	// 		 *   - Send the welcome email which prompts for verification (default)
	// 		 *   - Bypass the welcome email and automatically verify the email (commented out, below)
	// 		 */
	// 	const { email } = payload;

	// 	// New user
	// 	uid = await User.create({
	// 		username: payload.handle,
	// 		email, // if you uncomment the block below, comment this line out
	// 	});

	// 	// Automatically confirm user email
	// 	// await User.setUserField(uid, 'email', email);
	// 	// await UserEmail.confirmByUid(uid);
	// }

	// Save provider-specific information to the user
	// await User.setUserField(uid, `${constants.name}Id`, payload.oAuthid);
	// await db.setObjectField(`${constants.name}Id:uid`, payload.oAuthid, uid);

	// if (payload.isAdmin) {
	// 	await Groups.join('administrators', uid);
	// }

	// return {
	// 	uid: uid,
	// };
};

OAuth.getUidByOAuthid = async oAuthid => db.getObjectField(`${constants.name}Id:uid`, oAuthid);

OAuth.deleteUserData = function (data, callback) {
	const { uid } = data;
	async.waterfall([
		async.apply(User.getUserField, data.uid, `${constants.name}Id`),
		function (oAuthIdToDelete, next) {
			db.deleteObjectField(`${constants.name}Id:uid`, oAuthIdToDelete, next);
			User.setUserField(uid, `${constants.name}Id`, null);
		},
	], (err) => {
		if (err) {
			winston.error(`[sso-oauth] Could not remove OAuthId data for uid ${data.uid}. Error: ${err}`);
			return callback(err);
		}

		callback(null, data);
	});
};

// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
OAuth.whitelistFields = function (params, callback) {
	params.whitelist.push(`${constants.name}Id`);
	callback(null, params);
};
module.exports = OAuth;