class OAuth1:
	def __init__(self, credentials):
		if 'client_id' not in credentials:
			raise KeyError('Missing client ID')

		if 'client_secret' not in credentials:
			raise KeyError('Missing client secret')

		self.credentials = credentials

	def oauth_request(self, url, params={}):
		import time
		import math
		import urllib
		from .oauth import OAuth

		oauth = OAuth(
			self.credentials['client_id'],
			self.credentials['client_secret']
		)
		oauth.add_param('oauth_consumer_key', self.credentials['client_id'])
		oauth.add_param('oauth_nonce', oauth.generate_nonce())
		oauth.add_param('oauth_timestamp', str(math.floor(time.time())))
		oauth.add_param('oauth_version', '1.0')
		for param in params:
			oauth.add_param(param, params[param])
		oauth.set_request_method('POST')
		oauth.set_request_url(url)

		data = urllib.parse.urlencode({}).encode('utf8')
		req = urllib.request.Request(url, data) 
		req.add_header('User-Agent', 'Mozilla')
		req.add_header(*oauth.generate_header())

		return req

	def parse_oauth_response(self, response):
		oauth_response = {}
		fields = (response.read()).decode('utf8').split('&')
		for field in fields:
			pair = field.split('=')
			oauth_response[pair[0]] = pair[1]

		return oauth_response

	def requires_redirect(self):
		from flask import request
		if (
			'oauth_token' not in request.args
			or not request.args['oauth_token']
			or 'oauth_verifier' not in request.args
			or not request.args['oauth_verifier']
			):
			return True
		return False

	def authentication_uri(self, redirect_uri, state=''):
		from . import add_state
		redirect_uri = add_state(redirect_uri, state)

		req = self.oauth_request(
			self.access_token_uri,
			params={'oauth_callback': redirect_uri}
		)

		import urllib
		response = urllib.request.urlopen(req)
		if not response:
			raise ValueError('Empty access token response')

		oauth_token = self.parse_oauth_response(response)['oauth_token']
		return self.authentication_uri + oauth_token

	def authentication_value(self, redirect_uri):
		from flask import request
		params = {
			'oauth_token': request.args['oauth_token'],
			'oauth_verifier': request.args['oauth_verifier'],
		}
		req = self.oauth_request(self.user_info_uri, params=params)

		import urllib
		response = urllib.request.urlopen(req)
		if not response:
			raise ValueError('Empty user info response')

		user_info = self.parse_oauth_response(response)
		return self.get_user_id(user_info)
