from ioauth import Consumer
from ioauth import token_from_string
from ioauth import parse_path, parse_host, parse_port, parse_qs_real
from urllib import urlencode
import httplib

request_token_url = 'https://api.beatport.com/identity/1/oauth/request-token'
access_token_url = 'https://api.beatport.com/identity/1/oauth/access-token'
example_data_url = 'https://api.beatport.com/cart/1/'
consumer_key = 'b'
consumer_secret = 'a'

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
request_token = token_from_string(body)
login_url = dict(parse_qs_real(body))['login_url']

print 'Go here: '
print login_url
print
oauth_verifier = raw_input('Enter the OAuth Verifier: ')

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
