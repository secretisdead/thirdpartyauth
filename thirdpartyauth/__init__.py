def third_party_auth(service, credentials={}, useragent='Authentication App'):
	if 'twitter' == service:
		from . twitter_auth import TwitterAuth
		return TwitterAuth(credentials, useragent)
	elif 'google' == service:
		from . google_auth import GoogleAuth
		return GoogleAuth(credentials, useragent)
	elif 'patreon' == service:
		from . patreon_auth import PatreonAuth
		return PatreonAuth(credentials, useragent)
	elif 'discord' == service:
		from . discord_auth import DiscordAuth
		return DiscordAuth(credentials, useragent)
	elif 'github' == service:
		from . github_auth import GitHubAuth
		return GitHubAuth(credentials, useragent)
	elif 'twitch' == service:
		from . twitch_auth import TwitchAuth
		return TwitchAuth(credentials, useragent)
	elif 'steam' == service:
		from . steam_auth import SteamAuth
		return SteamAuth()
	else:
		raise ValueError('Unsupported authentication service')

def add_state(uri, state):
	if not state:
		return uri
	if -1 == uri.find('?'):
		uri += '?'
	else:
		uri += '&'
	import urllib
	return uri + 'state=' + urllib.parse.quote_plus(state)
