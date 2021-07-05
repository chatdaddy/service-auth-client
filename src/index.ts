export * from './OpenAPI/Auth'
import type { verify } from 'jsonwebtoken'
import { JWT, OAuthApiFp, Scope } from './OpenAPI/Auth'
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
    for(const scope of scopes) {
        const { number } = SCOPES[scope]
		if(str.length <= number) {
			while(str.length < number) {
				str += '0'
			}
			str += '1'
		} else {
			str = str.slice(0, number) + '1' + str.slice(number+1)
		}
    }
	return str
}

let verifyJWT: typeof verify
export const verifyToken = (token: string) => {
	if(!verifyToken) {
		verifyJWT = require('jsonwebtoken').verify
	}
	const user = verifyJWT(token, PUBLIC_KEY, { algorithms: [ 'ES256' ] }) as JWT
	return user
}

export const decodeToken = (token: string) => {
	const comps = token.split('.')
    const str = Buffer.from(comps[1], 'base64')?.toString('utf-8')
    return JSON.parse(str || '') as JWT
}

export const expiryDateOfToken = (jwt: JWT) => (new Date(jwt.iat * 1000))

export const hasScope = (user: JWT, scope: Scope) => (
	user.scope[ SCOPES[scope]?.number ] === '1'
)

/**
 * Checks whether this JWT token data has at least one of these scopes
 */
export const validateUserScopes = (user: JWT, ...scopes: Scope[]) => {
	if(!scopes.length) return { authorized: true, missingScopes: [] }
	
    const userScopes: string = user.scope
	const missingScopes = scopes.filter(scope => 
		userScopes[ SCOPES[scope]?.number ] !== '1'
	)
    const authorized = missingScopes.length < scopes.length
    return { authorized, missingScopes }
}

export const makeAccessTokenFactory = (
	refreshToken: string, 
	scopes: Scope[]
) => {
	const tokenAPI = OAuthApiFp()
    const tokenCache: { [_: string]: Promise<{ token: string, expiresAt: Date }> } = {

	}
	
    return (teamId?: string) => {
		const key = teamId || refreshToken
        let task = tokenCache[key]
        if(!task) {
            task = (async () => {
				const fetch = await tokenAPI.tokenPost({
					refreshToken,
					scopes,
					teamId: teamId as any
				})
				const { data: { access_token } } = await fetch()
				const jwt = decodeToken(access_token)
				const expiresAt = expiryDateOfToken(jwt)
                return {
					token: access_token,
					expiresAt
				}
            })()
			//@ts-ignore
            tokenCache[key] = task.catch(() => { delete tokenCache[key] })
        }
        return task
    }
}