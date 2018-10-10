import urllib

from flask import abort

from . import add_state
from . oauth2 import OAuth2

class GitHubAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state=''):
		uri = (
			'https://github.com/login/oauth/authorize'
				+ '?client_id=' + self.credentials['client_id']
				+ '&redirect_uri=' + urllib.parse.quote_plus(redirect_uri)
		)
		return add_state(uri, state)

	def authentication_value(self, redirect_uri, *args):
		self.access_token_uri = 'https://github.com/login/oauth/access_token'
		self.user_info_uri = 'https://api.github.com/user'
		self.get_user_id = lambda user_info: user_info['id']
		return super().authentication_value(
			redirect_uri,
			access_token_headers={'Accept': 'application/json'},
		)
