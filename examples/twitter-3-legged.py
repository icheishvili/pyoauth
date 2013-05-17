import hashlib
import pyoauth
import httplib
from time import time
from urlparse import parse_qsl

host = 'api.twitter.com'
port = 443
request_token_url = '/oauth/request_token'
access_token_url = '/oauth/access_token'
authorize_url = '/oauth/authorize'
example_data_url = '/1.1/friends/ids.json'
consumer_key = 'ZoNZyTXXiBFemfQEYXnmXw' #iliarm
consumer_secret = 'YH76M3mZoxslhYqQa8tKyThHHebG6zjplyQTfxFk' #iliarm

####################
# Request token step
####################
current_time = time()
params = {
    'oauth_callback': 'oob',
    'oauth_consumer_key': consumer_key,
    'oauth_nonce': hashlib.sha1(str(current_time)).hexdigest(),
    'oauth_signature_method': 'HMAC-SHA1',
    'oauth_timestamp': int(current_time),
    'oauth_version': 1.0,
}
signer = pyoauth.Signer(
    'https', 'POST', host, port,
    '%s?%s' % (request_token_url, pyoauth.url_encode(params)))
signer.consumer_secret_finder = lambda _x: consumer_secret
oauth_header = signer.make_oauth_header()

conn = httplib.HTTPSConnection(host, port)
conn.request(
    'POST', request_token_url, '', {'Authorization': oauth_header})
response = conn.getresponse()
status = response.status
body = response.read()
response.close()
conn.close()
if status != 200:
    raise ValueError(body)

response_params = dict(parse_qsl(body))
request_token_key = response_params['oauth_token']
request_token_secret = response_params['oauth_token_secret']

###########################################
# Authorization step (user gets redirected)
###########################################
print 'Go here: '
print 'https://%s%s?oauth_token=%s' % (
    host, authorize_url, request_token_key)
print
oauth_verifier = raw_input('Enter the OAuth Verifier: ').strip()

###################
# Access token step
###################
current_time += 1
params = {
    'oauth_consumer_key': consumer_key,
    'oauth_token': request_token_key,
    'oauth_nonce': hashlib.sha1(str(current_time)).hexdigest(),
    'oauth_signature_method': 'HMAC-SHA1',
    'oauth_timestamp': int(current_time),
    'oauth_version': 1.0,
}
signer = pyoauth.Signer(
    'https', 'POST', host, port,
    '%s?%s' % (access_token_url, pyoauth.url_encode(params)))
signer.consumer_secret_finder = lambda _x: consumer_secret
signer.token_secret_finder = lambda _x, _y: request_token_secret
oauth_header = signer.make_oauth_header()

conn = httplib.HTTPSConnection(host, port)
conn.request(
    'POST', '%s?oauth_verifier=%s' % (access_token_url, oauth_verifier), '',
    {'Authorization': oauth_header})
response = conn.getresponse()
status = response.status
body = response.read()
response.close()
conn.close()
if status != 200:
    raise ValueError(body)

response_params = dict(parse_qsl(body))
access_token_key = response_params['oauth_token']
access_token_secret = response_params['oauth_token_secret']

##################
# Example API call
##################
current_time += 1
params = {
    'oauth_consumer_key': consumer_key,
    'oauth_token': access_token_key,
    'oauth_nonce': hashlib.sha1(str(current_time)).hexdigest(),
    'oauth_signature_method': 'HMAC-SHA1',
    'oauth_timestamp': int(current_time),
    'oauth_version': 1.0,
}
signer = pyoauth.Signer(
    'https', 'GET', host, port,
    '%s?%s' % (example_data_url, pyoauth.url_encode(params)))
signer.consumer_secret_finder = lambda _x: consumer_secret
signer.token_secret_finder = lambda _x, _y: access_token_secret
oauth_header = signer.make_oauth_header()

conn = httplib.HTTPSConnection(host, port)
conn.request(
    'GET', '%s' % example_data_url, '',
    {'Authorization': oauth_header})
response = conn.getresponse()
status = response.status
body = response.read()
response.close()
conn.close()
print status, body
