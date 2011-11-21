import unittest
import ioauth
from time import time

TEST_INPUT_PARAMS = [
    ('b5', '=%3D'),
    ('a3', 'a'),
    ('c@', ''),
    ('a2', 'r b'),
    ('oauth_consumer_key', '9djdj82h48djs9d2'),
    ('oauth_token', 'kkk9d7dh3k39sjv7'),
    ('oauth_signature_method', 'HMAC-SHA1'),
    ('oauth_timestamp', '137131201'),
    ('oauth_nonce', '7d8f3e4a'),
    ('c2', ''),
    ('a3', '2 q')]

class TestEverything(unittest.TestCase):
    def test_parse_path(self):
        self.assertEquals(
            ioauth.parse_path('http://www.example.com/foo'), '/foo')

    def test_parse_host(self):
        self.assertEquals(
            ioauth.parse_host('http://www.example.com/foo'),
            'www.example.com')
        self.assertEquals(
            ioauth.parse_host('http://www.example.com:100/foo'),
            'www.example.com')

    def test_parse_port(self):
        self.assertEquals(
            ioauth.parse_port('http://www.example.com/foo'), 80)
        self.assertEquals(
            ioauth.parse_port('https://www.example.com/foo'), 443)
        self.assertEquals(
            ioauth.parse_port('https://www.example.com:7000/foo'), 7000)

    def test_encode_string(self):
        self.assertEquals(ioauth.encode_string('aAzZ109.-~_'), 'aAzZ109.-~_')
        self.assertEquals(ioauth.encode_string(' $/'), '%20%24%2F')

    def test_generate_nonce(self):
        self.assertNotEquals(ioauth.generate_nonce(), ioauth.generate_nonce())

    def test_generate_timestamp(self):
        self.assertEquals(int(time()), ioauth.generate_timestamp())

    def test_get_base_string_uri(self):
        self.assertEquals(
            ioauth.get_base_string_uri('http', 'example.com', '/foo'),
            'http://example.com/foo')
        self.assertEquals(
            ioauth.get_base_string_uri('https', 'example.com', '/foo'),
            'https://example.com/foo')
        self.assertEquals(
            ioauth.get_base_string_uri('https', 'example.com:7000', '/foo'),
            'https://example.com:7000/foo')

    def test_dict_to_proplist(self):
        self.assertEquals(
            ioauth.dict_to_proplist({'foo': 'bar', 'bar': 1}),
            [('foo', 'bar'), ('bar', 1)])

    def test_get_normalized_params(self):
        expected = [
            'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key',
            '=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method',
            '=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=',
            'kkk9d7dh3k39sjv7']
        self.assertEquals(
            ioauth.get_normalized_params(TEST_INPUT_PARAMS),
            ''.join(expected))

    def test_get_signature_base_string(self):
        expected = [
            'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%25',
            '20q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26',
            'oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a',
            '%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp',
            '%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7']
        self.assertEquals(
            ioauth.get_signature_base_string(
                'http', 'example.com', 'POST', '/request', TEST_INPUT_PARAMS),
            ''.join(expected))
             
    def test_token_from_string(self):
        expected = ioauth.Token('1key2', '3secret4')
        input_string = 'foo=bar&oauth_token=1key2&oauth_token_secret=3secret4'
        self.assertEquals(expected, ioauth.token_from_string(input_string))

    def test_parse_qs_real(self):
        self.assertEquals(
            ioauth.parse_qs_real('foo=bar&bar=1'),
            [('foo', 'bar'), ('bar', '1')])

    def test_SignatureHmacSha1(self):
        signature = ioauth.SignatureHmacSha1(
            'client_secret1', 'token_secret1')
        self.assertEquals(signature.get_name(), 'HMAC-SHA1')
        self.assertEquals(
            signature.sign('asdf'), 'WhUYhOftcBcm4ihduvCQKGaytog%3D')

    def test_SignaturePlaintext(self):
        signature = ioauth.SignaturePlaintext(
            'client_secret1', 'token_secret1')
        self.assertEquals(signature.get_name(), 'PLAINTEXT')
        self.assertEquals(
            signature.sign('asdf'), 'client_secret1&token_secret1')

    def test_Authorization(self):
        input_params = [
            ('oauth_callback', 'oob'),
            ('oauth_consumer_key', 'basdf89'),
            ('oauth_nonce', 'asdfk'),
            ('oauth_timestamp', '3947098'),
            ('oauth_version', '1.0'),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_signature', 'asdfkjads;fljasdp9f8')]
        expected = [
            'OAuth realm="",oauth_callback="oob",oauth_consumer_key=',
            '"basdf89",oauth_nonce="asdfk",oauth_timestamp="3947098",',
            'oauth_version="1.0",oauth_signature_method="HMAC-SHA1",',
            'oauth_signature="asdfkjads;fljasdp9f8"']
        authorization = ioauth.Authorization(input_params)
        self.assertEquals(authorization.get_header(), ''.join(expected))

        expected = [
            'OAuth realm="foo",oauth_callback="oob",oauth_consumer_key=',
            '"basdf89",oauth_nonce="asdfk",oauth_timestamp="3947098",',
            'oauth_version="1.0",oauth_signature_method="HMAC-SHA1",',
            'oauth_signature="asdfkjads;fljasdp9f8"']
        authorization = ioauth.Authorization(input_params, 'foo')
        self.assertEquals(authorization.get_header(), ''.join(expected))
