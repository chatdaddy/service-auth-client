# service-auth-client

ChatDaddy Authentication & Team Management SDK for NodeJS/Browser

## Refresh Tokens and Generating Them

We recommend you use refresh tokens to generate these short lived access tokens. The refresh token is immune to password changes & prevents you from ever entering the password in plaintext. The refresh token automatically becomes invalid after **14 Days** of inactivity. 

You do have to use your password to generate a refresh token.
``` ts
import { OAuthApi, encodeSHA256 } from '@chatdaddy/service-auth-client'

const getRefreshToken = async() => {
	const {
      data: { refresh_token },
    } = await oAuthApi.tokenPost({
      phoneNumber: 85212345678, // use your own ChatDaddy registered phone number
	  password: encodeSHA256('plaintextPassword'), // pass the SHA encoded password
      returnRefreshToken: true,
    })
	return refresh_token
}
console.log(getRefreshToken()) // prints something like "676be3ff-8d6e-4e74-8b0a-16e769d1ee80"
```

## Generating Access Tokens and Using Them

All of ChatDaddy's APIs rely on a single access point using the short lived JWT access token. The access token's schema can be read about [here](https://chatdaddy.stoplight.io/docs/openapi/repos/chatdaddy-service-auth/openapi.yaml/components/schemas/JWT).

Presently, all access tokens last for **1 hour**.

This SDK includes functions to easily generate and persist access tokens from refresh tokens
``` ts
import { OAuthApi, Scope, encodeSHA256 } from '@chatdaddy/service-auth-client'
// create a factory that takes care of auto-renewing access tokens when they expire
const getToken = makeAccessTokenFactory({
	request: {
		refreshToken: '676be3ff-8d6e-4e74-8b0a-16e769d1ee80', // example, use your own refresh token
		scopes: [Scope.MessagesSendToAll] // only add scopes to send messages
	},
})
;(async() => {
	// enter the team ID you want to generate the token for
	// read the section below to see how to get your team ID
	const token = await getToken('976bf2fe-ar6e-4e74-8b0a-16e769d1ee80')
	console.log(token)
	// above line would print something like "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// fetch chats from whatsapp using the fetched token
	fetch(
		'https://api-wa.chatdaddy.tech/chats?count=20',
		{
			headers: { 'authorization': `Bearer ${token}` }
		}
	)
})()

```

## Finding Out your Team ID

1. Login & open ChatDaddy App from `https://app.chatdaddy.tech`
2. Navigate to `https://app.chatdaddy.tech/settings/api`
3. Copy team ID from there

Example:
![example](/find-team-id.png)