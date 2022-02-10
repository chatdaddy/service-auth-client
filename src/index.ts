export * from './OpenAPI/Auth'
import type { verify } from 'jsonwebtoken'
import { createHash } from 'crypto'
import { Configuration, ConfigurationParameters, JWT, OAuthApi, RefreshTokenLoginRequest, Scope } from './OpenAPI/Auth'
import SCOPES from './scopes.json'

const PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEevVHEB81+mIuHJ6Ka2+GveuyAb2P
SNEGnm4K1V6HzZF0F9+mQS7N0UHNE+gv0OQIKi5D6e48ZCVytj3iX4Todg==
-----END PUBLIC KEY-----
`
const RETRY_WAIT_INTERVAL_MS = 500
// expire the token a little early to account for delays in network requests
const TOKEN_EXPIRY_MARGIN_MS = 60 * 1000 // 1 minute

/** exports the binary string used in auth tokens */
export const generateBinaryString = (scopes: Scope[]) => {
	let str = ''
	for (const scope of scopes) {
		const { number } = SCOPES[scope]
		if (str.length <= number) {
			while (str.length < number) {
				str += '0'
			}
			str += '1'
		} else {
			str = str.slice(0, number) + '1' + str.slice(number + 1)
		}
	}
	return str
}

let verifyJWT: typeof verify
/** verify an access token really is valid, returns the decoded object */
export const verifyToken = (token: string) => {
	if (!verifyJWT) {
		verifyJWT = require('jsonwebtoken').verify
	}
	const user = verifyJWT(token, PUBLIC_KEY, { algorithms: ['ES256'] }) as JWT
	return user
}
/** decodes a JWT token and returns the included object */
export const decodeToken = (token: string) => {
	const comps = token.split('.')
	const str = Buffer.from(comps[1], 'base64')?.toString('utf-8')
	return JSON.parse(str || '') as JWT
}
/** get the expiry date of a JWT token */
export const expiryDateOfToken = (jwt: JWT) => (new Date(jwt.exp * 1000))
/** get the scopes from a binary encoded string */
export const getScopes = (binary: string) => {
	const scopes: Scope[] = []
	for (const scope of Object.keys(SCOPES) as Scope[]) {
		if (binary[SCOPES[scope].number] === '1') {
			scopes.push(scope)
		}
	}
	return scopes
}
/** Checks whether this JWT token data has at least one of these scopes */
export const validateUserScopes = (user: JWT, ...scopes: Scope[]) => {
	if (!scopes.length) return { authorized: true, missingScopes: [] }

	const userScopes: string = user.scope
	const missingScopes = scopes.filter(scope =>
		userScopes[SCOPES[scope]?.number] !== '1'
	)
	const authorized = missingScopes.length < scopes.length
	return { authorized, missingScopes }
}
/** Options to create an access token for use in APIs */
export type AccessTokenFactoryOptions = {
	/** extra parameters like scopes to pass to the token generation request */
	request: Omit<RefreshTokenLoginRequest, 'teamId'>
	/** optional list of existing tokens to inject into the cache */
	existingTokens?: string[]
	/** optional config to generate the API client */
	config?: ConfigurationParameters
	/** max number of retries, 500ms delay between requests */
	maxRetries?: number 
}

export const makeAccessTokenFactory = (
	{ request, existingTokens, config, maxRetries }: AccessTokenFactoryOptions
) => {

	type TokenCache = { [_: string]: { token: Promise<string | { error: Error }>, expiresAt: Date | undefined } }

	existingTokens = existingTokens || []
	maxRetries = maxRetries || 1

	const tokenAPI = new OAuthApi(new Configuration(config || {}))
	const tokenCache: TokenCache = 
		existingTokens.reduce((dict, token) => {
			const jwt = decodeToken(token)
			const expiresAt = new Date(expiryDateOfToken(jwt).getTime() - TOKEN_EXPIRY_MARGIN_MS)
			if(expiresAt.getTime() > Date.now()) {
				dict[jwt.user.teamId] = { token: Promise.resolve(token), expiresAt }
			}
			return dict
		}, {} as TokenCache)

	const makeTokenApiRequest = async(req: RefreshTokenLoginRequest) => {
		let triesLeft = maxRetries
		while(true) {
			try {
				const result = await tokenAPI.tokenPost(req)
				return result
			} catch(error) {
				triesLeft -= 1
				// throw the error if it fails
				if(triesLeft <= 0) {
					throw error
				}
				// wait some time before retrying
				await new Promise(resolve => setTimeout(resolve, RETRY_WAIT_INTERVAL_MS))
			}
		}
	}

	return async (teamId: string) => {
		const key = teamId
		let task = tokenCache[key]
		if(!task || (!!task.expiresAt && (task.expiresAt?.getTime() < Date.now()))) {
			tokenCache[key] = {
				token: (async() => {
					try {
						const { data: { access_token } } = await makeTokenApiRequest(
							{ ...request, teamId }
						)
						const jwt = decodeToken(access_token)
						const expiresAt = new Date(expiryDateOfToken(jwt).getTime() - TOKEN_EXPIRY_MARGIN_MS)
						if(tokenCache[key]) {
							tokenCache[key]!.expiresAt = expiresAt
						}
						return access_token
					} catch(error) {
						delete tokenCache[key]
						return { error }
					}
				})(),
				expiresAt: undefined
			}
		}
		const result = tokenCache[key]
		const token = await result!.token
		if(typeof token === 'object') {
			throw token.error
		}
		return { token, expiresAt: result.expiresAt }
	}
}
/** get the SHA encoded value */
export const encodeSHA256 = (plaintext: string) => (
	createHash('sha256')
		.update(plaintext)
		.digest('base64')
)