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
