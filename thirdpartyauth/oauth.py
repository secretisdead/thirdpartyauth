def ksort(d):
	return [(k, d[k]) for k in sorted(d.keys())]

class OAuth:
	def __init__(self, consumer_key='', consumer_secret='', url=''):
		self.params = {}
		self.consumer_key = ''
		self.consumer_secret = ''
		self.token_secret = ''
		self.url = ''
		self.method = 'POST'
		self.signature = ''
		self.headers = {}

		self.set_consumer_key(consumer_key)
		self.set_consumer_secret(consumer_secret)
		self.set_request_url(url)

	def set_consumer_secret(self, consumer_secret):
		self.consumer_secret = consumer_secret

	def set_consumer_key(self, consumer_key):
		self.consumer_key = consumer_key

	def set_token_secret(self, token_secret):
		self.token_secret = token_secret

	def add_param(self, key, value):
		self.params[str(key).encode('utf8')] = str(value).encode('utf8')

	def remove_param(self, key):
		del self.params[key]

	def clear_params(self):
		self.params = {}

	def set_request_method(self, method):
		self.method = method.upper()

	def set_request_url(self, url):
		self.url = url.lower()

	def set_request_data(self, data):
		self.data = data

	def generate_nonce(self):
		import random
		import string

		return ''.join(
			random.choice(
				string.ascii_uppercase + string.ascii_lowercase + string.digits
			) for x in range(32)
		)

	def generate_header(self):
		import urllib

		self.sign()
		header = ''
		sorted_params = ksort(self.params)
		for key, value in sorted_params:
			header += (
				urllib.parse.quote_plus(key)
					+ '="'
					+ urllib.parse.quote_plus(value)
					+ '",'
			)

		header = header[:-1]
		return 'Authorization', 'OAuth ' + header

	def sign(self):
		import urllib

		self.add_param('oauth_signature_method', 'HMAC-SHA1')
		#self.add_param('oauth_signature_method', 'HMAC-SHA256')
		params_encoded = {}
		for k in self.params:
			key = urllib.parse.quote_plus(k)
			value = urllib.parse.quote_plus(self.params[k])
			params_encoded[key] = value
		param_string = ''
		sorted_params = ksort(params_encoded)
		for key, value in sorted_params:
			param_string += key + '=' + value + '&'
		param_string = param_string[:-1]
		base_string = (
			self.method
				+ '&'
				+ urllib.parse.quote_plus(self.url)
				+ '&'
				+ urllib.parse.quote_plus(param_string)
		).encode('utf8')
		signing_key = (
			urllib.parse.quote_plus(self.consumer_secret)
				+ '&'
				+ urllib.parse.quote_plus(self.token_secret)
		).encode('utf8')

		import hmac
		import hashlib
		hmac_digest = hmac.new(
			signing_key,
			base_string,
			hashlib.sha1
			#hashlib.sha256
		).digest()

		import base64
		self.signature = base64.b64encode(hmac_digest).decode('utf8')
		self.add_param('oauth_signature', self.signature)
