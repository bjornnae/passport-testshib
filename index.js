"use strict";
/**
 * TestShib Passport Authentication Module
 *
 * This module exposes a passport Strategy object that is pre-configured to
 * work with the TestShib's Shibboleth Identity Provider (IdP). To use this,
 * you must register your server with testshib.org. For details, see
 * https://github.com/ucsf-ckm/passport-testshib
 *
 * @module passport-testshib
 * @author Rich Trott
 */

var saml = require('passport-saml');
var util = require('util');

var idpCert = 'MIIEDjCCAvagAwIBAgIBADANBgkqhkiG9w0BAQUFADBnMQswCQYDVQQGEwJVUzEVMBMGA1UECBMMUGVubnN5bHZhbmlhMRMwEQYDVQQHEwpQaXR0c2J1cmdoMREwDwYDVQQKEwhUZXN0U2hpYjEZMBcGA1UEAxMQaWRwLnRlc3RzaGliLm9yZzAeFw0wNjA4MzAyMTEyMjVaFw0xNjA4MjcyMTEyMjVaMGcxCzAJBgNVBAYTAlVTMRUwEwYDVQQIEwxQZW5uc3lsdmFuaWExEzARBgNVBAcTClBpdHRzYnVyZ2gxETAPBgNVBAoTCFRlc3RTaGliMRkwFwYDVQQDExBpZHAudGVzdHNoaWIub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArYkCGuTmJp9eAOSGHwRJo1SNatB5ZOKqDM9ysg7CyVTDClcpu93gSP10nH4gkCZOlnESNgttg0r+MqL8tfJC6ybddEFB3YBo8PZajKSe3OQ01Ow3yT4I+Wdg1tsTpSge9gEz7SrC07EkYmHuPtd71CHiUaCWDv+xVfUQX0aTNPFmDixzUjoYzbGDrtAyCqA8f9CN2txIfJnpHE6q6CmKcoLADS4UrNPlhHSzd614kR/JYiks0K4kbRqCQF0Dv0P5Di+rEfefC6glV8ysC8dB5/9nb0yh/ojRuJGmgMWHgWk6h0ihjihqiu4jACovUZ7vVOCgSE5Ipn7OIwqd93zp2wIDAQABo4HEMIHBMB0GA1UdDgQWBBSsBQ869nh83KqZr5jArr4/7b+QazCBkQYDVR0jBIGJMIGGgBSsBQ869nh83KqZr5jArr4/7b+Qa6FrpGkwZzELMAkGA1UEBhMCVVMxFTATBgNVBAgTDFBlbm5zeWx2YW5pYTETMBEGA1UEBxMKUGl0dHNidXJnaDERMA8GA1UEChMIVGVzdFNoaWIxGTAXBgNVBAMTEGlkcC50ZXN0c2hpYi5vcmeCAQAwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjR29PhrCbk8qLN5MFfSVk98t3CT9jHZoYxd8QMRLI4j7iYQxXiGJTT1FXs1nd4Rha9un+LqTfeMMYqISdDDI6tv8iNpkOAvZZUosVkUo93pv1T0RPz35hcHHYq2yee59HJOco2bFlcsH8JBXRSRrJ3Q7Eut+z9uo80JdGNJ4/SJy5UorZ8KazGj16lfJhOBXldgrhppQBb0Nq6HKHguqmwRfJ+WkxemZXzhediAjGeka8nz8JjwxpUjAiSWYKLtJhGEaTqCYxCCX2Dw+dOTqUzHOZ7WKv4JXPK5G/Uhr8K/qhmFT2nIQi538n6rVYLeWj8Bbnl+ev0peYzxFyF5sQA==';
var idpEntryPoint = 'https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO';
var strategyName = 'testshib';

/**
 * Standard URLs for Shibboleth Metadata route and the Logout page
 * You can use the urls.metadata in conjunction with the metadataRoute
 * function to create your server's metadata route implementation.
 *
 * @type {{metadata: string, logoutUrl: string}}
 */
module.exports.urls = {
    metadata: '/Shibboleth.sso/Metadata',
    logoutUrl: 'https://idp.testshib.org/Shibboleth.sso/Logout'
};

//map of possible profile attributes and what name
//we should give them on the resulting user object
//add to this with other attrs if you request them
var profileAttrs = {
    'urn:oid:0.9.2342.19200300.100.1.1': 'netId',
    'urn:oid:2.5.4.3': 'cn',
    'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': 'principalName',
    'urn:oid:2.5.4.42': 'givenName',
    'urn:oid:2.5.4.20': 'phone',
    'urn:oid:2.5.4.4': 'surname'
};

function verifyProfile(profile, done) {
    if (!profile)
        return done(new Error('Empty SAML profile returned!'));
    else
        return done(null, convertProfileToUser(profile));
}

function convertProfileToUser(profile) {
    var user = {};
    var niceName;
    var idx;
    var keys = Object.keys(profile);
    var key;

    for (idx = 0; idx < keys.length; ++idx) {
        key = keys[idx];
        niceName = profileAttrs[key];
        if (niceName) {
            user[niceName] = profile[key];
        }
    }

    return user;    
}

/**
 * Passport Strategy for TestShib Shibboleth Authentication
 *
 * This class extends passport-saml.Strategy, providing the necessary options for the TestShib Shibboleth IdP
 * and converting the returned profile into a user object with sensible property names.
 *
 * @param {Object} options - Configuration options
 * @param {string} options.entityId - Your server's entity id (often same as domain name)
 * @param {string} options.domain - Your server's domain name
 * @param {number} options.port - Port your HTTPS server is running on (default: 443)
 * @param {string} options.callbackUrl - Relative URL for the login callback
 * @param {string} options.privateKey - Optional private key for signing SAML requests
 * @constructor
 */
module.exports.Strategy = function (options) {
    options = options || {};
    options.entryPoint = options.entryPoint || idpEntryPoint;
    options.cert = options.cert || idpCert;
    options.identifierFormat = null;
    options.issuer = options.issuer || options.entityId || options.domain;
    options.port = options.port || 443;
    options.callbackUrl = 'https://' + options.domain + ':' + options.port + options.callbackUrl;
    options.decryptionPvk = options.privateKey;
    options.privateCert = options.privateKey;


    saml.Strategy.call(this, options, verifyProfile);
    this.name = strategyName;
};


util.inherits(module.exports.Strategy, saml.Strategy);

/*
    Route implementation for the standard Shibboleth metadata route
    usage:
        var testshib = require(...);
        var strategy = new testshib.Strategy({...});
        app.get(testshib.urls.metadata, testshib.metadataRoute(strategy, myPublicCert));
*/

/**
 * Returns a route implementation for the standard Shibboleth metadata route.
 * common usage:
 *  var testshib = reuqire('passport-testshib');
 *  var myPublicCert = //...read public cert PEM file
 *  var strategy = new testshib.Strategy({...});
 *  app.get(testshib.urls.metadata, testshib.metadataRoute(strategy, myPublicCert));
 *
 * @param strategy - The new Strategy object from this module
 * @param publicCert - Your server's public certificate (typically loaded from a PEM file)
 * @returns {Function} - Route implementation suitable for handing to app.get()
 */
module.exports.metadataRoute = function(strategy, publicCert) {
    return function(req, res) {
        res.type('application/xml');
        res.status(200).send(strategy.generateServiceProviderMetadata(publicCert));
    }
}; //metadataRoute

/**
 * Middleware for ensuring that the user has authenticated.
 * You can use this in two different ways. If you pass this to app.use(), it will secure all routes
 * that are added to the app after that. Or you can use this selectively on routes by adding it as
 * the first route handler function, like so:
 *  app.get('/secure/route', ensureAuth(loginUrl), function(req, res) {...});
 *
 * @param loginUrl - The URL to redirect to if the user is not authenticated
 * @returns {Function} - Middleware function that ensures authentication
 */
module.exports.ensureAuth = function(loginUrl) {
    return function(req, res, next) {
        if (req.isAuthenticated())
            return next();
        else {
            if (req.session) {
                req.session.authRedirectUrl = req.url;
            }
            else {
                console.warn('passport-testshib: No session property on request!'
                    + ' Is your session store unreachable?')

            }
            res.redirect(loginUrl);
        }
    }
};

/*
    Middleware for redirecting back to the originally requested URL after
    a successful authentication. The ensureAuth() middleware above will
    capture the current URL in session state, and when your callback route
    is called, you can use this to get back to the originally-requested URL.
    usage:
        var testshib = require(...);
        var strategy = new testshib.Strategy({...});
        app.get('/login', passport.authenticate(strategy.name));
        app.post('/login/callback', passport.authenticate(strategy.name), testshib.backtoUrl());
        app.use(testshib.ensureAuth('/login'));
*/
/**
 * Middleware for redirecting back to the originally requested URL after a successful authentication.
 * The ensureAuth() middleware in this same module will capture the current URL in session state, and
 * you can use this method to get back to the originally-requested URL during your login callback route.
 * Usage:
 *  var testshib = require('passport-testshib');
 *  var strategy = new testshib.Strategy({...});
 *  app.get('/login', passport.authenticate(strategy.name));
 *  app.post('/login/callback', passport.authenticate(strategy.name), testshib.backToUrl());
 *  app.use(testshib.ensureAuth('/login'));
 *  //...rest of routes
 *
 * @param defaultUrl - Optional default URL to use if no redirect URL is in session state (defaults to '/')
 * @returns {Function} - Middleware function that redirects back to originally requested URL
 */
module.exports.backToUrl = function(defaultUrl) {
    return function(req, res) {
        var url = defaultUrl || '/';
        if (req.session) {
            url = req.session.authRedirectUrl || url;
            delete req.session.authRedirectUrl;
        }
        res.redirect(url);
    }
};

