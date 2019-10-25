export interface TokenOptions {
	key?: string;
	email?: string;
	iss?: string;
	sub?: string;
	scope?: string | string[];
	additionalClaims?: {};
}

export interface TokenData {
	expires_in?: number;
	refresh_token?: string;
	access_token?: string;
	token_type?: string;
	id_token?: string;
}

export type AccessToken = TokenData['access_token'];

export declare class GoogleToken {
	key?: string;
	email?: string;
	iss?: string;
	sub?: string;
	scope?: string | string[];
	additionalClaims?: {};

	token?: AccessToken;
	expiresAt?: number;

	constructor(opts?: TokenOptions);

	isExpired(): boolean;
	configure(opts?: TokenOptions): void;

	getToken(): Promise<AccessToken> | void;
	requestToken(): Promise<AccessToken> | void;
	revokeToken(): Promise<void> | void;
}
