class OAuth2:
	def __init__(self, credentials):
		if 'client_id' not in credentials:
			raise KeyError('Missing client ID')

		if 'client_secret' not in credentials:
			raise KeyError('Missing client secret')

		self.credentials = credentials

	def requires_redirect(self):
		from flask import request
		if 'code' not in request.args:
			return True
		return False

	def authentication_value(self, redirect_uri):
		import urllib
		import json

		from flask import request

		data = urllib.parse.urlencode({
			'code': request.args['code'],
			'grant_type': 'authorization_code',
			'client_id': self.credentials['client_id'],
			'client_secret': self.credentials['client_secret'],
			'redirect_uri': redirect_uri,
		}).encode('utf8')
		req = urllib.request.Request(self.access_token_uri, data)
		req.add_header('User-Agent', 'Mozilla')

		response = urllib.request.urlopen(req)
		if not response:
			raise ValueError('Empty access token response')

		access_token = json.loads(response.read())['access_token']
			
		req = urllib.request.Request(self.user_info_uri) 
		req.add_header('Authorization', 'Bearer ' + access_token)
		req.add_header('User-Agent', 'Mozilla')

		response = urllib.request.urlopen(req)
		if not response:
			raise ValueError('Empty user info response')

		user_info = json.loads(response.read())
		return self.get_user_id(user_info)

class GoogleAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state=''):
		import urllib
		from . import add_state
		uri = (
			'https://accounts.google.com/o/oauth2/v2/auth'
				+ '?response_type=code'
				+ '&client_id=' + self.credentials['client_id']
				+ '&redirect_uri=' + urllib.parse.quote_plus(redirect_uri)
				+ '&scope=profile'
		)
		return add_state(uri, state)

	def authentication_value(self, redirect_uri, *args):
		self.access_token_uri = 'https://www.googleapis.com/oauth2/v4/token'
		self.user_info_uri = (
			'https://www.googleapis.com/oauth2/v1/userinfo'
				+ '?alt=json'
		)
		self.get_user_id = lambda user_info: user_info['id']
		return super().authentication_value(redirect_uri)

class PatreonAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state=''):
		import urllib
		from . import add_state
		uri = (
			'https://www.patreon.com/oauth2/authorize'
				+ '?response_type=code'
				+ '&client_id=' + self.credentials['client_id']
				+ '&redirect_uri=' + urllib.parse.quote_plus(redirect_uri)
				+ '&scope=users'
		)
		return add_state(uri, state)

	def authentication_value(self, redirect_uri, *args):
		self.access_token_uri = 'https://api.patreon.com/oauth2/token'
		self.user_info_uri = 'https://api.patreon.com/oauth2/api/current_user'
		self.get_user_id = lambda user_info: user_info['data']['id']
		return super().authentication_value(redirect_uri)

class DiscordAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state=''):
		import urllib
		from . import add_state
		uri = (
			'https://discordapp.com/api/oauth2/authorize'
				+ '?response_type=code'
				+ '&client_id=' + self.credentials['client_id']
				+ '&redirect_uri=' + urllib.parse.quote_plus(redirect_uri)
				+ '&scope=identify'
		)
		return add_state(uri, state)

	def authentication_value(self, redirect_uri, *args):
		self.access_token_uri = 'https://discordapp.com/api/oauth2/token'
		self.user_info_uri = 'https://discordapp.com/api/users/@me'
		self.get_user_id = lambda user_info: user_info['id']
		return super().authentication_value(redirect_uri)

class TwitchAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state):
		import urllib
		from . import add_state
		uri = (
			'https://api.twitch.tv/kraken/oauth2/authorize'
				+ '?response_type=code'
				+ '&client_id=' + self.credentials['client_id']
				+ '&redirect_uri=' + urllib.parse.quote_plus(redirect_uri)
				+ '&scope=user:read:email'
		)
		return add_state(uri, state)

	def authentication_value(self, redirect_uri, *args):
		self.access_token_uri = 'https://api.twitch.tv/kraken/oauth2/token'
		self.user_info_uri = 'https://api.twitch.tv/helix/users'
		self.get_user_id = lambda user_info: user_info['data'][0]['id']
		return super().authentication_value(redirect_uri)
