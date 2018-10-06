import urllib

from . import add_state
from . oauth2 import OAuth2

class GoogleAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state=''):
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
