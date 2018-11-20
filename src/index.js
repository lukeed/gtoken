/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import { readFile } from 'fs';
import { extname } from 'path';
import { promisify } from 'util';
import { get, post } from 'httpie';
import { sign } from 'jws';
import encode from 'qss';

const read = promisify(readFile);

const GOOGLE_TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token';
const GOOGLE_REVOKE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/revoke?token=';

const alg = 'RS256';
const grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

export class GoogleToken {
	constructor(opts) {
		this.configure(opts);
	}

	isExpired() {
		return Date.now() >= (this.token && this.expiresAt);
	}

	/**
	 * Returns a cached token or retrieves a new one from Google.
	 * @param callback   The callback function.
	 */
	getToken(callback) {
		if (callback) {
			this.getTokenAsync().then(t => {
				callback(null, t);
			}).catch(callback);
			return;
		}
		return this.getTokenAsync();
	}

	/**
	 * Given a keyFile, extract the key and client email if available
	 * @param keyFile Path to a json, or pem file that contains the key.
	 * @returns an object with privkey and email properties
	 */
	async getCredentials(keyFile) {
		const ext = extname(keyFile);

		if (ext === '.json') {
			const key = await read(keyFile, 'utf8');
			const { private_key, client_email } = JSON.parse(key);
			if (!private_key || !client_email) throw new Error('private_key and client_email are required.');
			return { privkey:private_key, email:client_email };
		}

		if (ext === '.pem') {
			const privkey = await read(keyFile, 'utf8');
			return { privkey };
		}

		throw new Error('Unknown certificate type! Only *.json and *.pem files are supported.');
	}

	async getTokenAsync() {
		if (!this.isExpired()) {
			return Promise.resolve(this.token);
		}

		if (!this.key && !this.keyFile) {
			throw new Error('No key or keyFile set.');
		}

		if (!this.key && this.keyFile) {
			const obj = await this.getCredentials(this.keyFile);
			this.iss = obj.email || this.iss;
			this.key = obj.privkey;
			if (!this.iss) {
				throw new Error('email is required');
			}
		}

		return this.requestToken();
	}

	/**
	 * Revoke the token if one is set.
	 * @param callback   The callback function.
	 */
	revokeToken(callback) {
		if (callback) {
			this.revokeTokenAsync().then(() => callback()).catch(callback);
			return;
		}
		return this.revokeTokenAsync();
	}

	async revokeTokenAsync() {
		if (!this.token) {
			throw new Error('No token to revoke.');
		}
		return get(GOOGLE_REVOKE_TOKEN_URL + this.token).then(r => {
			this.configure({
				key: this.key,
				scope: this.scope,
				keyFile: this.keyFile,
				additionalClaims: this.additionalClaims,
				email: this.iss,
				sub: this.sub,
			});
		});
	}


	/**
	 * Configure the GoogleToken for re-use.
	 * @param  {object} opts  Configuration object.
	 */
	configure(opts={}) {
		this.key = opts.key;
		this.keyFile = opts.keyFile;
		this.iss = opts.email || opts.iss;
		this.additionalClaims = opts.additionalClaims;
		this.token = this.expiresAt = this.rawToken = null;
		this.scope = Array.isArray(opts.scope) ? opts.scope.join(' ') : opts.scope;
		this.sub = opts.sub;
	}

	/**
	 * Request the token from Google.
	 */
	async requestToken() {
		const iat = Math.floor(Date.now() / 1e3);

		const payload = Object.assign({
			iss: this.iss,
			scope: this.scope,
			aud: GOOGLE_TOKEN_URL,
			exp: iat + 3600,
			sub: this.sub,
			iat,
		}, this.additionalClaims);

		const assertion = sign({ header:{ alg }, payload, secret:this.key });
		const uri = encode({ grant_type, assertion }, GOOGLE_TOKEN_URL + '?');
		const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

		return post(uri, { headers }).then(r => {
			this.rawToken = r.data;
			this.token = r.data.access_token;
			this.expiresAt = (r.data.expires_in == null) ? null : (iat + r.data.expires_in!) * 1e3;
			return this.token;
		}).catch(err => {
			this.token = null;
			this.tokenExpires = null;
			const body = err.data || {};
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
