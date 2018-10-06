from . openid import OpenID

class SteamAuth(OpenID):
	def authentication_uri(self, redirect_uri, state=''):
		self.auth_uri = 'https://steamcommunity.com/openid'
		return super().authentication_uri(redirect_uri, state)

	def authentication_value(self, redirect_uri, state=''):
		self.get_identity = lambda identity: identity[identity.rfind('/') + 1:]
		return super().authentication_value(redirect_uri, state)
