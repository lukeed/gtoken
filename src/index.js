/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import { stringify } from 'querystring';
import { send } from 'httpie';
import { sign } from 'jws';

const GOOGLE_TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token';
const GOOGLE_REVOKE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/revoke?token=';

const alg = 'RS256';
const grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

export class GoogleToken {
	constructor(opts) {
		this.configure(opts);
	}

	isExpired() {
		return Date.now() >= (this.token && this.expiresAt);
	}

	/**
	 * Configure the GoogleToken for re-use.
	 */
	configure(opts={}) {
		this.key = opts.key;
		this.iss = opts.email || opts.iss;
		this.additionalClaims = opts.additionalClaims;
		this.token = this.expiresAt = this.rawToken = null;
		this.scope = Array.isArray(opts.scope) ? opts.scope.join(' ') : opts.scope;
		this.sub = opts.sub;
	}

	/**
	 * Returns a cached token or retrieves a new one from Google.
	 */
	async getToken() {
		if (!this.isExpired()) {
			return Promise.resolve(this.token);
		}

		if (!this.key) {
			throw new Error('No key set.');
		}

		return this.requestToken();
	}

	/**
	 * Revoke the token if one is set.
	 */
	async revokeToken() {
		if (!this.token) {
			throw new Error('No token to revoke.');
		}

		return send('GET', GOOGLE_REVOKE_TOKEN_URL + this.token).then(r => {
			this.configure({
				key: this.key,
				scope: this.scope,
				additionalClaims: this.additionalClaims,
				email: this.iss,
				sub: this.sub,
			});
		});
	}

	/**
	 * Request the token from Google.
	 */
	async requestToken() {
		let iat = Math.floor(Date.now() / 1e3);

		let payload = Object.assign({
			iss: this.iss,
			scope: this.scope,
			aud: GOOGLE_TOKEN_URL,
			exp: iat + 3600,
			sub: this.sub,
			iat,
		}, this.additionalClaims);

		let assertion = sign({ header:{ alg }, payload, secret:this.key });
		let body = stringify({ grant_type, assertion });

		return send('POST', GOOGLE_TOKEN_URL, { headers, body }).then(r => {
			this.rawToken = r.data;
			this.token = r.data.access_token;
			this.expiresAt = (r.data.expires_in == null) ? null : (iat + r.data.expires_in) * 1e3;
			return this.token;
		}).catch(err => {
			this.token = null;
			this.expiresAt = null;
			let body = err.data || {};
			if (body.error) {
				let msg = String(body.error);
				if (body.error_description) msg += `: ${body.error_description}`;
				throw new Error(msg);
			} else {
				throw err;
			}
		});
	}
}
