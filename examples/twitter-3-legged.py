from pyoauth import Consumer
from pyoauth import token_from_string
from pyoauth import parse_path, parse_host, parse_port, parse_qs_real
from urllib import urlencode
import httplib

request_token_url = 'https://api.twitter.com/oauth/request_token'
access_token_url = 'https://api.twitter.com/oauth/access_token'
authorize_url = 'https://api.twitter.com/oauth/authorize'
example_data_url = 'https://api.twitter.com/friends/ids'
consumer_key = ''
consumer_secret = ''

consumer = Consumer(consumer_key, consumer_secret)
params = {'oauth_callback': 'oob'}
signature = consumer.sign_request(request_token_url, 'POST', params)
headers = {'Authorization': signature.get_header()}

conn = httplib.HTTPSConnection(
    parse_host(request_token_url),
    parse_port(request_token_url))
conn.request('POST', parse_path(request_token_url), '', headers)
response = conn.getresponse()

body = response.read()
conn.close()

request_token = token_from_string(body)

print 'Go here: '
print '%s?oauth_token=%s' % (authorize_url, request_token.key)
print
oauth_verifier = raw_input('Enter the OAuth Verifier: ')

conn = httplib.HTTPSConnection(
    parse_host(request_token_url),
    parse_port(request_token_url))
consumer = Consumer(consumer_key, consumer_secret, request_token)
params = {'oauth_verifier': oauth_verifier}
signature = consumer.sign_request(access_token_url, 'POST', params)
headers = {'Authorization': signature.get_header()}
conn.request('POST', parse_path(access_token_url), urlencode(params), headers)
response = conn.getresponse()
body = response.read()
access_token = token_from_string(body)

consumer = Consumer(consumer_key, consumer_secret, access_token)
signature = consumer.sign_request(example_data_url)
headers = {'Authorization': signature.get_header()}
conn.request('GET', parse_path(example_data_url), '', headers)
response = conn.getresponse()
body = response.read()
print body
conn.close()
