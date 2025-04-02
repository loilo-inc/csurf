/*!
 * csurf
 * Copyright(c) 2011 Sencha Inc.
 * Copyright(c) 2014 Jonathan Ong
 * Copyright(c) 2014-2016 Douglas Christopher Wilson
 * MIT Licensed
 *
 * thanks to Douglas ..etc
 * Copyright(c) 2022- Loilo Inc.
 */

import type express from "express";
import Tokens from "csrf";
import Cookie from "cookie";
import createError from "http-errors";
import { sign } from "cookie-signature";

declare global {
  namespace Express {
    interface Request {
      csrfToken(): string;
    }
  }
}

interface CookieOptions extends express.CookieOptions {
  /**
   * @default '_csrf'
   */
  key?: string | undefined;
}

export type CsrfOptions = {
  value?: ((req: express.Request) => string) | undefined;
  cookie?: CookieOptions | boolean | undefined;
  ignoreMethods?: string[] | undefined;
  sessionKey?: string | undefined;
};

/**
 * CSRF protection middleware.
 *
 * This middleware adds a `req.csrfToken()` function to make a token
 * which should be added to requests which mutate
 * state, within a hidden form field, query-string etc. This
 * token is validated against the visitor's session.
 *
 * @param {Object} options
 * @return {Function} middleware
 * @public
 */

function csurf(options?: CsrfOptions): express.RequestHandler {
  const opts = options || {};

  // get cookie options
  const cookie = getCookieOptions(opts.cookie);

  // get session options
  const sessionKey = opts.sessionKey || "session";

  // get value getter
  const value = opts.value || defaultValue;

  // token repo
  const tokens = new Tokens();

  // ignored methods
  const ignoreMethods =
    opts.ignoreMethods === undefined
      ? ["GET", "HEAD", "OPTIONS"]
      : opts.ignoreMethods;

  if (!Array.isArray(ignoreMethods)) {
    throw new TypeError("option ignoreMethods must be an array");
  }

  // generate lookup
  const ignoreMethod = getIgnoredMethods(ignoreMethods);

  return function csrf(
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) {
    // validate the configuration against request
    if (!verifyConfiguration(req, sessionKey, cookie)) {
      return next(new Error("misconfigured csrf"));
    }
    // get the secret from the request
    let secret = getSecret(req, sessionKey, cookie);
    let token: string;

    // lazy-load token getter
    req.csrfToken = function csrfToken() {
      let sec = !cookie ? getSecret(req, sessionKey, cookie) : secret;

      // use cached token if secret has not changed
      if (token && sec === secret) {
        return token;
      }

      // generate & set new secret
      if (sec === undefined) {
        sec = tokens.secretSync();
        setSecret(req, res, sessionKey, sec, cookie);
      }

      // update changed secret
      secret = sec;

      // create new token
      token = tokens.create(secret);

      return token;
    };

    // generate & set secret
    if (!secret) {
      secret = tokens.secretSync();
      setSecret(req, res, sessionKey, secret, cookie);
    }

    // verify the incoming token
    if (!ignoreMethod[req.method] && !tokens.verify(secret, value(req))) {
      return next(
        createError(403, "invalid csrf token", {
          code: "EBADCSRFTOKEN",
        }),
      );
    }

    next();
  };
}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue(req: express.Request) {
  return (
    (req.body && req.body._csrf) ||
    (req.query && req.query._csrf) ||
    req.headers["csrf-token"] ||
    req.headers["xsrf-token"] ||
    req.headers["x-csrf-token"] ||
    req.headers["x-xsrf-token"]
  );
}

/**
 * Get options for cookie.
 *
 * @param {boolean|object} [options]
 * @returns {object}
 * @api private
 */

function getCookieOptions(options: any) {
  if (options !== true && typeof options !== "object") {
    return undefined;
  }

  const opts = Object.create(null);

  // defaults
  opts.key = "_csrf";
  opts.path = "/";

  if (options && typeof options === "object") {
    for (var prop in options) {
      var val = options[prop];

      if (val !== undefined) {
        opts[prop] = val;
      }
    }
  }

  return opts;
}

/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods(methods: any) {
  const obj = Object.create(null);

  for (var i = 0; i < methods.length; i++) {
    var method = methods[i].toUpperCase();
    obj[method] = true;
  }

  return obj;
}

/**
 * Get the token secret from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecret(req: express.Request, sessionKey: string, cookie: any) {
  // get the bag & key
  const bag = getSecretBag(req, sessionKey, cookie);
  const key = cookie ? cookie.key : "csrfSecret";

  if (!bag) {
    throw new Error("misconfigured csrf");
  }

  // return secret from bag
  return bag[key];
}

/**
 * Get the token secret bag from the request.
 *
 * @param {IncomingMessage} req
 * @param {String} sessionKey
 * @param {Object} [cookie]
 * @api private
 */

function getSecretBag(req: express.Request, sessionKey: string, cookie: any) {
  if (cookie) {
    // get secret from cookie
    var cookieKey = cookie.signed ? "signedCookies" : "cookies";
    // @ts-ignore
    return req[cookieKey];
  } else {
    // get secret from session
    // @ts-ignore
    return req[sessionKey];
  }
}

/**
 * Set a cookie on the HTTP response.
 *
 * @param {OutgoingMessage} res
 * @param {string} name
 * @param {string} val
 * @param {Object} [options]
 * @api private
 */

function setCookie(
  res: express.Response,
  name: string,
  val: string,
  options: any,
) {
  const data = Cookie.serialize(name, val, options);

  const prev = res.getHeader("set-cookie") || [];
  const header = Array.isArray(prev) ? prev.concat(data) : [prev, data];

  res.setHeader("set-cookie", header as string[]);
}

/**
 * Set the token secret on the request.
 *
 * @param {IncomingMessage} req
 * @param {OutgoingMessage} res
 * @param {string} sessionKey
 * @param {string} val
 * @param {Object} [cookie]
 * @api private
 */

function setSecret(
  req: express.Request,
  res: express.Response,
  sessionKey: string,
  val: string,
  cookie: any,
) {
  if (cookie) {
    // set secret on cookie
    let value = val;

    if (cookie.signed && req.secret) {
      value = "s:" + sign(val, req.secret);
    }

    setCookie(res, cookie.key, value, cookie);
  } else {
    // set secret on session
    // @ts-ignore
    req[sessionKey].csrfSecret = val;
  }
}

/**
 * Verify the configuration against the request.
 * @private
 */

function verifyConfiguration(
  req: express.Request,
  sessionKey: string,
  cookie: any,
) {
  if (!getSecretBag(req, sessionKey, cookie)) {
    return false;
  }

  if (cookie && cookie.signed && !req.secret) {
    return false;
  }

  return true;
}

export default csurf;
module.exports = csurf;
