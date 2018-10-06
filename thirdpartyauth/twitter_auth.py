from . oauth1 import OAuth1

class TwitterAuth(OAuth1):
	def authentication_uri(self, redirect_uri, state=''):
		self.access_token_uri = 'https://api.twitter.com/oauth/request_token'
		self.authentication_uri = (
			'https://api.twitter.com/oauth/authenticate'
				+ '?oauth_token='
		)
		return super().authentication_uri(redirect_uri, state)

	def authentication_value(self, redirect_uri, *args):
		self.user_info_uri = 'https://api.twitter.com/oauth/access_token'
		self.get_user_id = lambda user_info: user_info['user_id']
		return super().authentication_value(redirect_uri)
