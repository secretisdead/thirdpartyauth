services = {
	'twitter': 'oauth1',
	'google': 'oauth2',
	'patreon': 'oauth2',
	'discord': 'oauth2',
	'twitch': 'oauth2',
	'steam': 'openid',
}
methods = {
	'oauth1': {
		'twitter',
	},
	'oauth2': {
		'google',
		'patreon',
		'discord',
		'twitch',
	},
	'openid': {
		'steam',
	}
}

def third_party_auth(service, credentials={}):
	if service not in services:
		raise ValueError('Unknown authentication service')

	# OAuth1
	if service in methods['oauth1']:
		from . import oauth1
		if 'twitter' == service:
			return oauth1.TwitterAuth(credentials)
	# OAuth2
	elif service in methods['oauth2']:
		from . import oauth2
		if 'google' == service:
			return oauth2.GoogleAuth(credentials)
		elif 'patreon' == service:
			return oauth2.PatreonAuth(credentials)
		elif 'discord' == service:
			return oauth2.DiscordAuth(credentials)
		elif 'twitch' == service:
			return oauth2.TwitchAuth(credentials)

	# OpenID
	elif service in methods['openid']:
		from . import openid
		if 'steam' == service:
			return openid.SteamAuth()

	raise ValueError('Unknown authentication method')

def add_state(uri, state):
	if not state:
		return uri
	if -1 == uri.find('?'):
		uri += '?'
	else:
		uri += '&'
	import urllib
	return uri + 'state=' + urllib.parse.quote_plus(state)
