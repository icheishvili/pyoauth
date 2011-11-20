from ioauth import Consumer
from ioauth import token_from_string, parse_path, parse_host, parse_port
from urllib import urlencode
import httplib

request_token_url = 'https://api.beatport.com/identity/1/oauth/request-token'
direct_access_token_url = 'https://api.beatport.com/identity/1/oauth/direct-access-token'
example_data_url = 'https://api.beatport.com/cart/1/'
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
request_token = token_from_string(body)

consumer = Consumer(consumer_key, consumer_secret, request_token)
params = {'username': 'xxxxxxxxx', 'password': 'xxxxxxxxx'}
signature = consumer.sign_request(direct_access_token_url, 'POST', params)
headers = {
    'Authorization': signature.get_header(),
    'Content-Type': 'application/x-www-form-urlencoded'
}
conn.request(
    'POST',
    parse_path(direct_access_token_url),
    urlencode(params),
    headers)
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
