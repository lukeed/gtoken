/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */

import { readFile } from 'fs';
import { extname } from 'path';
import { promisify } from 'util';
import { sign } from 'jws';
import {request} from 'gaxios';

const read = promisify(readFile);

const GOOGLE_TOKEN_URL = 'https://www.googleapis.com/oauth2/v4/token';
const GOOGLE_REVOKE_TOKEN_URL = 'https://accounts.google.com/o/oauth2/revoke?token=';

export interface Credentials {
	privateKey: string;
	clientEmail?: string;
}

export interface TokenData {
	refresh_token?: string;
	expires_in?: number;
	access_token?: string;
	token_type?: string;
	id_token?: string;
}

export interface TokenOptions {
	keyFile?: string;
	key?: string;
	email?: string;
	iss?: string;
	sub?: string;
	scope?: string|string[];
	additionalClaims?: {};
}

class ErrorWithCode extends Error {
	constructor(message: string, public code: string) {
		super(message);
	}
}

export class GoogleToken {
	token?: string|null = null;
	expiresAt?: number|null = null;
	key?: string;
	keyFile?: string;
	iss?: string;
	sub?: string;
	scope?: string;
	rawToken: TokenData|null = null;
	tokenExpires: number|null = null;
	email?: string;
	additionalClaims?: {};

	/**
	 * Create a GoogleToken.
	 *
	 * @param options  Configuration object.
	 */
	constructor(options?: TokenOptions) {
		this.configure(options);
	}

	/**
	 * Returns whether the token has expired.
	 *
	 * @return true if the token has expired, false otherwise.
	 */
	hasExpired() {
		return Date.now() >= (this.token && this.expiresAt);
	}

	/**
	 * Returns a cached token or retrieves a new one from Google.
	 *
	 * @param callback The callback function.
	 */
	getToken(): Promise<string|null|undefined>;
	getToken(callback: (err: Error|null, token?: string|null|undefined) => void):
			void;
	getToken(callback?: (err: Error|null, token?: string|null|undefined) => void):
			void|Promise<string|null|undefined> {
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
	 * @returns an object with privateKey and clientEmail properties
	 */
	async getCredentials(keyFile: string): Promise<Credentials> {
		switch (extname(keyFile)) {
			case '.json': {
				const key = await read(keyFile, 'utf8');
				const { private_key, client_email } = JSON.parse(key);
				if (!private_key || !client_email) {
					throw new ErrorWithCode(
							'private_key and client_email are required.',
							'MISSING_CREDENTIALS');
				}
				return { privateKey:private_key, clientEmail:client_email };
			}
			case '.pem': {
				const privateKey = await read(keyFile, 'utf8');
				return { privateKey };
			}
			default:
				throw new ErrorWithCode(
						'Unknown certificate type. Type is determined based on file extension. ' +
								'Current supported extensions are *.json and *.pem.',
						'UNKNOWN_CERTIFICATE_TYPE');
		}
	}

	private async getTokenAsync(): Promise<string|null|undefined> {
		if (!this.hasExpired()) {
			return Promise.resolve(this.token);
		}

		if (!this.key && !this.keyFile) {
			throw new Error('No key or keyFile set.');
		}

		if (!this.key && this.keyFile) {
			const { privateKey, clientEmail } = await this.getCredentials(this.keyFile);
			this.key = privateKey;
			this.iss = clientEmail || this.iss;
			clientEmail || this.ensureEmail();
		}
		return this.requestToken();
	}

	private ensureEmail() {
		if (!this.iss) {
			throw new ErrorWithCode('email is required.', 'MISSING_CREDENTIALS');
		}
	}

	/**
	 * Revoke the token if one is set.
	 *
	 * @param callback The callback function.
	 */
	revokeToken(): Promise<void>;
	revokeToken(callback: (err?: Error) => void): void;
	revokeToken(callback?: (err?: Error) => void): void|Promise<void> {
		if (callback) {
			this.revokeTokenAsync().then(() => callback()).catch(callback);
			return;
		}
		return this.revokeTokenAsync();
	}

	private async revokeTokenAsync() {
		if (!this.token) {
			throw new Error('No token to revoke.');
		}
		return request({url: GOOGLE_REVOKE_TOKEN_URL + this.token}).then(r => {
			this.configure({
				email: this.iss,
				sub: this.sub,
				key: this.key,
				keyFile: this.keyFile,
				scope: this.scope,
				additionalClaims: this.additionalClaims,
			});
		});
	}


	/**
	 * Configure the GoogleToken for re-use.
	 * @param  {object} options Configuration object.
	 */
	private configure(options: TokenOptions = {}) {
		this.keyFile = options.keyFile;
		this.key = options.key;
		this.token = this.expiresAt = this.rawToken = null;
		this.iss = options.email || options.iss;
		this.sub = options.sub;
		this.additionalClaims = options.additionalClaims;
		this.scope = Array.isArray(options.scope)
			? options.scope.join(' ')
			: options.scope;
	}

	/**
	 * Request the token from Google.
	 */
	private async requestToken(): Promise<string|null|undefined> {
		const iat = Math.floor(Date.now() / 1e3);

		const payload = Object.assign({
			iss: this.iss,
			scope: this.scope,
			aud: GOOGLE_TOKEN_URL,
			exp: iat + 3600,
			sub: this.sub,
			iat,
		}, this.additionalClaims);

		const header = { alg: 'RS256' };
		const grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
		const assertion = sign({ header, payload, secret:this.key });

		return request<TokenData>({
			method: 'POST',
			url: GOOGLE_TOKEN_URL,
			data: { grant_type, assertion },
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
		}).then(r => {
			this.rawToken = r.data;
			this.token = r.data.access_token;
			this.expiresAt = (r.data.expires_in == null) ? null : (iat + r.data.expires_in!) * 1e3;
			return this.token;
		}).catch(err => {
			this.token = null;
			this.tokenExpires = null;
			const body = (err.response && err.response.data) ? err.response.data : {};
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
