import urllib

from . import add_state
from . oauth2 import OAuth2

class PatreonAuth(OAuth2):
	def authentication_uri(self, redirect_uri, state=''):
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
