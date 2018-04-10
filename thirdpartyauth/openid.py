class OpenID:
	def requires_redirect(self):
		from flask import request
		if 'openid.identity' not in request.args:
			return True
		return False

	def authentication_uri(self, redirect_uri, state=''):
		from openid.consumer import consumer
		csm = consumer.Consumer({}, None)
		csm.consumer.openid1_nonce_query_arg_name = 'jnonce'

		protocol_end = redirect_uri.find('//')
		realm_end = redirect_uri.find('/', protocol_end + 2)

		realm = redirect_uri
		if -1 != realm_end:
			realm = redirect_uri[:realm_end]

		from . import add_state
		redirect_uri = add_state(redirect_uri, state)

		auth_req = csm.begin(self.auth_uri)
		return auth_req.redirectURL(realm, return_to=redirect_uri)

	def authentication_value(self, redirect_uri, state=''):
		from flask import request
		from openid.consumer import consumer
		csm = consumer.Consumer({}, None)
		csm.consumer.openid1_nonce_query_arg_name = 'jnonce'

		from . import add_state
		redirect_uri = add_state(redirect_uri, state)

		if 'jnonce' in request.args:
			redirect_uri += request.args['jnonce']

		result = csm.complete(request.args, redirect_uri)

		if consumer.SuccessResponse != type(result):
			raise ArithmeticError('Failed OpenID validation')

		return self.get_identity(request.args['openid.identity'])

class SteamAuth(OpenID):
	def authentication_uri(self, redirect_uri, state=''):
		self.auth_uri = 'https://steamcommunity.com/openid'
		return super().authentication_uri(redirect_uri, state)

	def authentication_value(self, redirect_uri, state=''):
		self.get_identity = lambda identity: identity[identity.rfind('/') + 1:]
		return super().authentication_value(redirect_uri, state)
