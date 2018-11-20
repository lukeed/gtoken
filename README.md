# node-gtoken [![Build Status](https://badgen.now.sh/travis/lukeed/gtoken)](https://travis-ci.org/lukeed/gtoken)

Node.js Google Authentication Service Account Tokens

> **Important:** This fork will change according to _my_ needs and **will not be maintained** for public use!

## Installation

``` sh
npm install @lukeed/gtoken
```

## Usage

```js
const { GoogleToken } = require('@lukeed/gtoken');
const gtoken = new GoogleToken({
  email: 'my_service_account_email@developer.gserviceaccount.com',
  scope: ['https://scope1', 'https://scope2'], // or space-delimited string of scopes
  key: '-----BEGIN RSA PRIVATE KEY-----\nXXXXXXXXXXX...'
});

const token = await gtoken.getToken()
console.log(token);
```

Or with promises:

```js
gtoken.getToken()
  .then(token => {
    console.log(`Token: ${token}`)
  })
  .catch(e => console.error);
```

## Options

> Various options that can be set when creating initializing the `gtoken` object.

- `options.email or options.iss`: The service account email address.
- `options.scope`: An array of scope strings or space-delimited string of scopes.
- `options.sub`: The email address of the user requesting delegated access.
- `options.key`: The raw RSA private key value

### .getToken()

> Returns the cached token or requests a new one and returns it.

``` js
await gtoken.getToken();
```

### Properties

> Various properties set on the gtoken object after call to `.getToken()`.

- `gtoken.token`: The access token.
- `gtoken.expiresAt`: The expiry date as milliseconds since 1970/01/01
- `gtoken.key`: The raw key value.
- `gtoken.rawToken`: Most recent raw token data received from Google.

### .isExpired()

> Returns true if the token has expired, or token does not exist.

``` js
gtoken.isExpired(); // false
```

### .revokeToken()

> Revoke the token if set.

``` js
await gtoken.revokeToken();
```


## License

(MIT) Copyright 2018 Google LLC

