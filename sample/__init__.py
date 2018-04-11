from flask import Flask, Response, url_for

app = Flask(__name__)

@app.route('/')
def services_list():
	services_list = ''
	from thirdpartyauth import services
	for service in services:
		services_list += (
			'<a href="' + url_for('sign_in', service=service) + '">'
				+ service
				+ '</a><br>'
		)
	return Response(services_list, mimetype='text/html')

@app.route('/sign-in/<service>')
def sign_in(service):
	from flask import abort

	from thirdpartyauth import services
	if service not in services:
		abort(400, 'Requested sign-in service not available')

	try:
		f = open('credentials.json', 'r')
	except FileNotFoundError:
		abort(500, 'Missing credentials file')

	import json
	try:
		credentials = json.load(f)
	except json.decoder.JSONDecodeError:
		abort(500, 'Malformed credentials file')

	service_credentials = {}
	if service in credentials:
		service_credentials = credentials[service]

	from thirdpartyauth import third_party_auth
	try:
		auth = third_party_auth(service, service_credentials)
	except KeyError as e:
		abort(500, e)
	except ValueError as e:
		abort(400, e)

	redirect_uri = url_for('authentication_landing', _external=True)

	if auth.requires_redirect():
		try:
			authentication_uri = auth.authentication_uri(
				redirect_uri,
				'sign_in,' + service
			)
		except urllib.error.HTTPError as e:
			abort(500, e)
		except urllib.error.URLError as e:
			abort(500, e)
		except ValueError as e:
			abort(500, e)
		except ArithmeticError as e:
			abort(400, e)

		from flask import redirect
		return redirect(authentication_uri)

	try:
		value = auth.authentication_value(redirect_uri, 'sign_in,' + service)
	except urllib.error.HTTPError as e:
		abort(500, e)
	except urllib.error.URLError as e:
		abort(500, e)
	except ValueError as e:
		abort(500, e)
	except ArithmeticError as e:
		abort(400, e)

	return Response(
		'received user identifier: <strong>'
			+ value
			+ '</strong> from service <strong>'
			+ service
			+ '</strong>',
		mimetype='text/html'
	)

@app.route('/authenticate')
def authentication_landing():
	from flask import request, abort, redirect

	if 'state' in request.args:
		state = request.args['state']
	elif 'openid.state' in request.args:
		state = request.args['openid.state']
	else:
		abort(400, 'No auth state returned')

	state_parts = state.split(',')
	endpoint = state_parts[0]
	service = state_parts[1]

	kwargs = {}
	# oauth 2 passes code
	if 'code' in request.args:
		kwargs['code'] = request.args['code']
	# openid passes all request args
	elif 'openid.identity' in request.args:
		kwargs = request.args
	# oauth1 passes oauth_ args
	else:
		for arg in request.args:
			if 'oauth_' == arg[:6]:
				kwargs[arg] = request.args[arg]

	return redirect(url_for(endpoint, service=service, **kwargs))
