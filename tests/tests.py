import unittest
from nose.tools import raises
import pyoauth


class TestEverything(unittest.TestCase):
    def test_parse_header(self):
        test_table = [
            ('foo=bar,bar=foo',                                     [('foo', 'bar'), ('bar', 'foo')]),
            ('foo=bar, foo=baz, bar=foo',                           [('foo', 'bar'), ('foo', 'baz'), ('bar', 'foo')]),
            ('foo=bar,  bar=foo',                                   [('foo', 'bar'), ('bar', 'foo')]),
            ('foo=bar     ,  bar=foo',                              [('foo', 'bar'), ('bar', 'foo')]),
            ('foo="bar",bar="foo"',                                 [('foo', 'bar'), ('bar', 'foo')]),
            ('foo="b,ar",bar="foo"',                                [('foo', 'b,ar'), ('bar', 'foo')]),
            ('"foo"="bar","bar"="foo"',                             [('foo', 'bar'), ('bar', 'foo')]),
            ('"foo\\"%s%s"="bar","bar"="foo"' % (chr(92), chr(92)), [('foo"\\', 'bar'), ('bar', 'foo')]),
            ('"foo"="bar\\"%s%s","bar"="foo"' % (chr(92), chr(92)), [('foo', 'bar"\\'), ('bar', 'foo')]),
            ('"foo"="bar","bar\\"%s%s"="foo"' % (chr(92), chr(92)), [('foo', 'bar'), ('bar"\\', 'foo')]),
            ('"foo"="bar","bar"="\\"%s%sfoo"' % (chr(92), chr(92)), [('foo', 'bar'), ('bar', '"\\foo')]),
            ('foo="bar",foo="more",foo="extra"',                    [('foo', 'bar'), ('foo', 'more'), ('foo', 'extra')]),
        ]
        for input_string, expected_result in test_table:
            actual_result = pyoauth.parse_header(input_string)
            self.assertEquals(expected_result, actual_result)

    @raises(pyoauth.SignatureException)
    def test_no_signature_method(self):
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', 80, '/?oauth_signature_method=magik')
        signer.get_signature()

    @raises(pyoauth.ValidationException)
    def test_invalid_nonce_timestamp(self):
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', '80', '/')
        signer.timestamp_and_nonce_validator = lambda x, y, z: False
        signer.get_signature()

    def test_oauth_header_parsing(self):
        authorization = ','.join([
            'OAuth realm="test"',
            'oauth_callback="oob"',
            'oauth_consumer_key="b"',
            'oauth_nonce="2W54W9"',
            'oauth_timestamp="1332630750"',
            'oauth_version="1.0"',
            'oauth_signature_method="HMAC-SHA1"',
            'oauth_signature="UxOtOUQLMr%2Fk%2B9DckYfKG4Y4xvM%3D"',
        ])
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', 80, '/',
            {'Authorization': authorization})
        self.assertEquals('test', signer.realm)

        expected_params = {
            'oauth_callback':         'oob',
            'oauth_consumer_key':     'b',
            'oauth_nonce':            '2W54W9',
            'oauth_timestamp':        '1332630750',
            'oauth_version':          '1.0',
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_signature':        'UxOtOUQLMr/k+9DckYfKG4Y4xvM=',
        }
        actual_params = signer.auth_header_params
        self.assertEquals(expected_params, actual_params)

    def test_ignore_body(self):
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', 80, '/', {}, 'a=b&b=c')
        self.assertEquals([], signer.params)

    def test_process_body(self):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', '80', '/?a=f', headers, 'a=b&b=c')
        expected_params = [('a', 'f'), ('a', 'b'), ('b', 'c')]
        self.assertEquals(expected_params, signer.params)

    def test_body_with_specified_charset(self):
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', '80', '/?a=f', headers, 'a=b&b=c')
        expected_params = [('a', 'f'), ('a', 'b'), ('b', 'c')]
        self.assertEquals(expected_params, signer.params)

    def test_signature(self):
        authorization = ','.join([
            'OAuth realm=""',
            'oauth_consumer_key=""',
            'oauth_signature_method="HMAC-SHA1"',
            'oauth_timestamp="1332631878"',
            'oauth_nonce="6e2b4b1f9824d919071106c01964eb15"',
            'oauth_version="1.0"',
            'oauth_signature="clol1a02imIYi8hzZVll4HjWIYs%3D"',
        ])
        headers = {'Authorization': authorization}
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', 80, '/', headers)
        expected_signature = 'clol1a02imIYi8hzZVll4HjWIYs='
        self.assertEquals(expected_signature, signer.get_signature())

    def test_make_request_header(self):
        params = {
            'oauth_version':          '1.0',
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp':        1234567890,
            'oauth_nonce':            'asdf1234',
            'oauth_consumer_key':     'consumerasdf',
            'oauth_callback':         'http://example.net/',
        }
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', 80, '/?%s' % pyoauth.url_encode(params))
        signer.realm = 'admins'

        expected_header = ','.join([
            'OAuth realm="admins"',
            'oauth_callback="http%3A%2F%2Fexample.net%2F"',
            'oauth_consumer_key="consumerasdf"',
            'oauth_nonce="asdf1234",'
            'oauth_signature="jxhGaw6dKp7PMHuy1P0TbyvfWqI%3D"',
            'oauth_signature_method="HMAC-SHA1"',
            'oauth_timestamp="1234567890"',
            'oauth_version="1.0"',
        ])
        self.assertEquals(expected_header, signer.make_oauth_header())

    def test_make_access_header(self):
        params = {
            'oauth_version':          '1.0',
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp':        1234567890,
            'oauth_nonce':            'asdf1234',
            'oauth_consumer_key':     'consumerasdf',
            'oauth_callback':         'http://example.net/',
            'oauth_token':            'tokenasdf',
        }
        signer = pyoauth.Signer(
            'http', 'GET', 'localhost', 80, '/?%s' % pyoauth.url_encode(params))
        signer.realm = 'admins'

        expected_header = ','.join([
            'OAuth realm="admins"',
            'oauth_callback="http%3A%2F%2Fexample.net%2F"',
            'oauth_consumer_key="consumerasdf"',
            'oauth_nonce="asdf1234"',
            'oauth_signature="6xtmCsWZCcSky02%2BScTH7M%2FQvqw%3D"',
            'oauth_signature_method="HMAC-SHA1"',
            'oauth_timestamp="1234567890"',
            'oauth_token="tokenasdf"',
            'oauth_version="1.0"',
        ])
        self.assertEquals(expected_header, signer.make_oauth_header())
