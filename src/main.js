import crypto from 'crypto'
import ClientOAuth2 from 'client-oauth2'

const {
	PUBLIC_URL,
	REACT_APP_API_HOST,
	REACT_APP_API_OAUTH,
	REACT_APP_OAUTH_CLIENT_ID,
	REACT_APP_OAUTH_REDIRECT_URI,
	REACT_APP_OAUTH_LOGOUT_URI,
} = process.env

const STATE_KEY = 'oauth/state'
const VERIFIER_KEY = 'oauth/verifierCode'
const CURRENT_URI_KEY = 'oauth/currentUri'
const ACCESS_TOKEN_KEY = 'oauth/accessToken'

function base64URLEncode(str) {
	return str.toString('base64')
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '')
}

function sha256(buffer) {
	return crypto.createHash('sha256').update(buffer).digest()
}

function restoreLoginLocation() {
	const redirectUri = localStorage.getItem(CURRENT_URI_KEY)
	localStorage.removeItem(CURRENT_URI_KEY)
	window.location.href = redirectUri ? redirectUri : PUBLIC_URL
}

const OAuth = new ClientOAuth2({
	clientId: REACT_APP_OAUTH_CLIENT_ID,
	accessTokenUri: REACT_APP_API_OAUTH + '/token',
	authorizationUri: REACT_APP_API_OAUTH + '/authorize',
	redirectUri: REACT_APP_OAUTH_REDIRECT_URI,
})

export const getAccessToken = () => localStorage.getItem(ACCESS_TOKEN_KEY)
export const setAccessToken = (token) => localStorage.setItem(ACCESS_TOKEN_KEY, token)
export const isAuthorized = () => !!getAccessToken()

export const setBaseUrl = (uri) => {
	if (!/^http/.test(uri)) {
		return REACT_APP_API_HOST + uri
	}

	return uri
}

export const signUrl = (url) => {
	if (/^data/.test(url)) return url
	let separator = '?'
	if (url.match(/\?/)) {
		separator = '&'
	}
	return setBaseUrl(url) + separator + 'Authorization=Bearer%20' + getAccessToken()
}

export const login = () => {
	// Save current uri
	localStorage.setItem(CURRENT_URI_KEY, window.location.href)

	const verifier = base64URLEncode(crypto.randomBytes(32))
	const codeChallenge = base64URLEncode(sha256(verifier))
	localStorage.setItem(VERIFIER_KEY, verifier)

	const state = Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5)
	localStorage.setItem(STATE_KEY, state)
	window.location.href = OAuth.code.getUri({
		query: {
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
			state,
		},
	})
}

export const getToken = () => {
	OAuth.code
		.getToken(window.location.href, {
			body: {
				code_verifier: localStorage.getItem(VERIFIER_KEY),
				state: localStorage.getItem(STATE_KEY),
			},
		})
		.then(user => {
			const {access_token} = user.data

			localStorage.setItem(ACCESS_TOKEN_KEY, access_token)
			localStorage.removeItem(VERIFIER_KEY)
			localStorage.removeItem(STATE_KEY)
			restoreLoginLocation()
		})
		.catch(console.log)
}

export const logout = (relogin) => {
	localStorage.removeItem(ACCESS_TOKEN_KEY)
	if (window.location.pathname === PUBLIC_URL + '/signout') {
		return
	}

	if (relogin) {
		login()
	} else {
		window.location.href = REACT_APP_OAUTH_LOGOUT_URI
	}
}

export default OAuth