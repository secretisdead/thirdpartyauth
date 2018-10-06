from openid.consumer import consumer
from flask import request

from . import add_state

class OpenID:
	def requires_redirect(self):
		if 'openid.identity' not in request.args:
			return True
		return False

	def authentication_uri(self, redirect_uri, state=''):
		csm = consumer.Consumer({}, None)
		csm.consumer.openid1_nonce_query_arg_name = 'jnonce'

		protocol_end = redirect_uri.find('//')
		realm_end = redirect_uri.find('/', protocol_end + 2)

		realm = redirect_uri
		if -1 != realm_end:
			realm = redirect_uri[:realm_end]

		redirect_uri = add_state(redirect_uri, state)

		auth_req = csm.begin(self.auth_uri)
		return auth_req.redirectURL(realm, return_to=redirect_uri)

	def authentication_value(self, redirect_uri, state=''):
		csm = consumer.Consumer({}, None)
		csm.consumer.openid1_nonce_query_arg_name = 'jnonce'

		redirect_uri = add_state(redirect_uri, state)

		if 'jnonce' in request.args:
			redirect_uri += request.args['jnonce']

		result = csm.complete(request.args, redirect_uri)

		if consumer.SuccessResponse != type(result):
			raise ArithmeticError('Failed OpenID validation')

		return self.get_identity(request.args['openid.identity'])
