export * from './OpenAPI/Auth'
import type { verify } from 'jsonwebtoken'
import { Configuration, ConfigurationParameters, JWT, OAuthApi, RefreshTokenLoginRequest, Scope } from './OpenAPI/Auth'
import SCOPES from './scopes.json'

const PUBLIC_KEY = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEevVHEB81+mIuHJ6Ka2+GveuyAb2P
SNEGnm4K1V6HzZF0F9+mQS7N0UHNE+gv0OQIKi5D6e48ZCVytj3iX4Todg==
-----END PUBLIC KEY-----
`
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
export const verifyToken = (token: string) => {
	if (!verifyJWT) {
		verifyJWT = require('jsonwebtoken').verify
	}
	const user = verifyJWT(token, PUBLIC_KEY, { algorithms: ['ES256'] }) as JWT
	return user
}

export const decodeToken = (token: string) => {
	const comps = token.split('.')
	const str = Buffer.from(comps[1], 'base64')?.toString('utf-8')
	return JSON.parse(str || '') as JWT
}

export const expiryDateOfToken = (jwt: JWT) => (new Date(jwt.exp * 1000))

export const hasScope = (user: JWT, scope: Scope) => (
	user.scope[SCOPES[scope]?.number] === '1'
)

export const getScopes = (binary: string) => {
	const scopes: Scope[] = []
	for (const scope of Object.keys(SCOPES) as Scope[]) {
		if (binary[SCOPES[scope].number] === '1') {
			scopes.push(scope)
		}
	}
	return scopes
}

/**
 * Checks whether this JWT token data has at least one of these scopes
 */
export const validateUserScopes = (user: JWT, ...scopes: Scope[]) => {
	if (!scopes.length) return { authorized: true, missingScopes: [] }

	const userScopes: string = user.scope
	const missingScopes = scopes.filter(scope =>
		userScopes[SCOPES[scope]?.number] !== '1'
	)
	const authorized = missingScopes.length < scopes.length
	return { authorized, missingScopes }
}

export type AccessTokenFactoryOptions = {
	request: Omit<RefreshTokenLoginRequest, 'teamId'>
	existingTokens?: string[]
	config?: ConfigurationParameters
}
type TokenCache = { [_: string]: { token: Promise<string>, expiresAt: Date | undefined } }
export const makeAccessTokenFactory = (
	{ request, existingTokens, config }: AccessTokenFactoryOptions
) => {
	existingTokens = existingTokens || []
	const tokenAPI = new OAuthApi(new Configuration(config || {}))
	const tokenCache: TokenCache = 
		existingTokens.reduce((dict, token) => {
			const jwt = decodeToken(token)
			const expiresAt = expiryDateOfToken(jwt)
			if(expiresAt.getTime() > Date.now()) {
				dict[jwt.user.teamId] = { token: Promise.resolve(token), expiresAt }
			}
			return dict
		}, {} as TokenCache)

	return async (teamId: string) => {
		const key = teamId
		let task = tokenCache[key]
		if(!task || (!!task.expiresAt && (task.expiresAt?.getTime() < Date.now()))) {
			tokenCache[key] = {
				token: (async () => {
					try {
						const { data: { access_token } } = await tokenAPI.tokenPost(
							{ ...request, teamId }
						)
						const jwt = decodeToken(access_token)
						const expiresAt = expiryDateOfToken(jwt)
						if(tokenCache[key]) {
							tokenCache[key]!.expiresAt = expiresAt
						}
						return access_token
					} catch(error) {
						delete tokenCache[key]
					}
				})(),
				expiresAt: undefined
			}
		}
		const result = tokenCache[key]
		const token = await result?.token
		if(!token) {
			throw new Error('failed to obtain token')
		}
		return { token, expiresAt: result.expiresAt }
	}
}