"""
pyoauth is a Python library for dealing with OAuth.
"""

import hmac
try:
    from hashlib import md5, sha1
except ImportError:
    from md5 import md5
    import sha as sha1
from datetime import datetime
from time import time
from binascii import b2a_base64
from urllib import quote
from urlparse import urlparse
try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

OAUTH_VERSION = '1.0'

def parse_path(url):
    """
    Convenience function to return the path of a URL.
    """
    return urlparse(url)[2]

def parse_host(url):
    """
    Convenience function to return the host of a URL.
    """
    host = urlparse(url)[1]
    if ':' in host:
        return host.split(':')[0]
    else:
        return host

def parse_port(url):
    """
    Convenience function to return the port of a URL (can be implied
    by the scheme).
    """
    parsed = urlparse(url)
    host = parsed[1]
    scheme = parsed[0]
    if ':' in host:
        return int(host.split(':')[1])
    else:
        if scheme == 'https':
            return 443
        else:
            return 80

def encode_string(input_string):
    """
    Convert string to UTF-8 and encode it per
    http://tools.ietf.org/html/rfc5849#section-3.6
    """
    if not isinstance(input_string, basestring):
        input_string = str(input_string)
    return quote(input_string.encode('utf-8'), safe='~')

def generate_nonce():
    """
    Generate a unique nonce as described by
    http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return md5(str(datetime.now())).hexdigest()

def generate_timestamp():
    """
    Generate a timestamp as described by
    http://tools.ietf.org/html/rfc5849#section-3.3
    """
    return int(time())

def get_base_string_uri(scheme, host, path):
    """
    Generate base string as described by
    http://tools.ietf.org/html/rfc5849#section-3.4.1.2
    """
    if scheme == 'https':
        port = 443
    else:
        port = 80
    send_port = False
    if ':' in host:
        host, parsed_port = host.split(':')
        parsed_port = int(parsed_port)
        if port != parsed_port:
            send_port = True
            port = parsed_port

    if send_port:
        return '%s://%s:%s%s' % (scheme, host, port, path)
    else:
        return '%s://%s%s' % (scheme, host, path)

def dict_to_proplist(input_dict):
    """
    Convert a dictionary to a property list (list of tuples). The
    tuples are pairs (key, value).
    """
    return zip(input_dict.keys(), input_dict.values())

def get_normalized_params(params):
    """
    Get normalized request parameters as described by
    http://tools.ietf.org/html/rfc5849#section-3.4.1.3
    """
    encoded = [(encode_string(k), encode_string(v)) for k, v in params]
    encoded.sort(key=lambda x: x[1])
    encoded.sort(key=lambda x: x[0])
    pairs = ['%s=%s' % (k, v) for k, v in encoded]
    return '&'.join(pairs)

def get_signature_base_string(scheme, host, method, path, params):
    """
    Get the full signature base string as described by
    http://tools.ietf.org/html/rfc5849#section-3.4.1
    """
    signature_base_string = []
    signature_base_string.append(encode_string(method))
    signature_base_string.append('&')
    signature_base_string.append(
        encode_string(get_base_string_uri(scheme, host, path)))
    signature_base_string.append('&')
    signature_base_string.append(
        encode_string(get_normalized_params(params)))
    return ''.join(signature_base_string)

def token_from_string(input_string):
    """
    Parse a url-encoded string containing token information to make a
    new Token object.
    """
    parsed = parse_qs(input_string, True, True)
    return Token(parsed['oauth_token'][0], parsed['oauth_token_secret'][0])

def parse_qs_real(input_string):
    """
    Parse a query string into a property list of key => value.
    """
    return [(k, v[0]) for k, v in dict_to_proplist(parse_qs(input_string))]

class Signature(object):
    """
    The base signature class. All signature classes inherit from this
    class.
    """

    def __init__(self, client_secret=None, token_secret=None):
        """
        Process client and token secret parameters, defaulting them to
        empty strings if they are not set.
        """
        if client_secret is None:
            self.client_secret = ''
        else:
            self.client_secret = client_secret
        if token_secret is None:
            self.token_secret = ''
        else:
            self.token_secret = token_secret

class SignatureHmacSha1(Signature):
    """
    The most popular OAuth signing mechanism. Uses a hashing mechanism
    based on sha1.

    See http://tools.ietf.org/html/rfc5849#section-3.4.2 for details
    """

    def __init__(self, client_secret=None, token_secret=None):
        """
        Defer to superclass implementation of secret key processing.
        """
        super(SignatureHmacSha1, self).__init__(client_secret, token_secret)

    def get_name(self):
        """
        Get the name of the signature method (will be sent as
        oauth_signature_method).
        """
        return 'HMAC-SHA1'

    def sign(self, msg):
        """
        Signs the given message (the signature base string) using the
        given secret keys.
        """
        key = '%s&%s' % (
            encode_string(self.client_secret),
            encode_string(self.token_secret))
        signature = hmac.new(key, msg, sha1)
        return encode_string(b2a_base64(signature.digest())[:-1])

class SignaturePlaintext(Signature):
    """
    An insecure, easy-to-debug signature mechanism. Should only be
    used over an encrypted connection (SSL/TLS), as it does not
    provide any security of its own.

    See http://tools.ietf.org/html/rfc5849#section-3.4.4 for details
    """

    def __init__(self, client_secret=None, token_secret=None):
        """
        Defer to superclass implementation of secret key processing.
        """
        super(SignaturePlaintext, self).__init__(client_secret, token_secret)

    def get_name(self):
        """
        Get the name of the signature method (will be sent as
        oauth_signature_method).
        """
        return 'PLAINTEXT'

    def sign(self, _msg):
        """
        Signs the given message (the signature base string) using the
        given secret keys.
        """
        return '%s&%s' % (
            encode_string(self.client_secret),
            encode_string(self.token_secret))

class Token(object):
    """
    Represents a single Token object (a combination of a publicly
    known key and a private secret).
    """

    def __init__(self, key, secret):
        """
        Set the key and secret.
        """
        self.key = key
        self.secret = secret

    def __eq__(self, other):
        """
        Test two token objects for equality.
        """
        return self.key == other.key and self.secret == other.secret
    
    def __str__(self):
        """
        Return a string-based representation of the Token.
        """
        return 'Token: key: %s, secret: %s' % (self.key, self.secret)

    def __repr__(self):
        """
        Return a Python-based representation of the Token (can be
        copy-pasted as Python source to re-create the same object).
        """
        return 'Token(%s, %s)' % (self.key, self.secret)

class Authorization(object):
    """
    Represents the parameters that make up a full OAuth signature.
    """

    def __init__(self, params, realm=''):
        """
        Set up the object with the parameters needed and an optional
        Realm.
        """
        self.params = []
        for key, val in params:
            if key[0:6] == 'oauth_':
                self.params.append((key, val))
        self.realm = realm

    def get_header(self):
        """
        Transform the OAuth information contained in this object into
        a HTTP-style header (should be set under the Authorization
        header). See http://tools.ietf.org/html/rfc5849#section-3.5.1
        for details.
        """
        str_params = []
        for key, val in self.params:
            str_params.append(('%s="%s"' % (key, val)))
        return 'OAuth realm="%s",%s' % (
            self.realm, ','.join(str_params))

    def __repr__(self):
        """
        Return a Python-based representation of the Token (can be
        copy-pasted as Python source to re-create the same object).
        """
        return 'Authorization(%s, %s)' % (self.params, self.realm)

class Consumer(object):
    """
    Used to sign whole HTTP requests with the given consumer and token
    information.
    """

    signer_class = SignatureHmacSha1

    def __init__(self, key, secret, token=None):
        """
        Set the given information on the consumer object and
        instantiate a signer.
        """
        self.key = key
        self.token = token
        token_secret = ''
        if token:
            token_secret = token.secret
        self.signer = self.signer_class(secret, token_secret)

    def sign_request(self, url, method=None, more_params=None):
        """
        Given the full URL, method, and additional parameters, as well
        as the information given when constructing the object, return
        an instance of Authorization that represents the OAuth
        signature.
        """
        if method is None:
            method = 'GET'

        parsed = urlparse(url)
        scheme = parsed[0]
        host = parsed[1].lower()
        path = parsed[2]
        sign_params = parse_qs_real(parsed[4])
    
        if more_params is not None:
            if type(more_params) == dict:
                sign_params += dict_to_proplist(more_params)
            elif isinstance(more_params, basestring):
                sign_params += parse_qs_real(more_params)
            else:
                sign_params = sign_params + more_params

        sign_params.append(('oauth_consumer_key', self.key))
        if self.token is not None:
            sign_params.append(('oauth_token', self.token.key))
        sign_params.append(('oauth_signature_method', self.signer.get_name()))
        sign_params.append(('oauth_timestamp', generate_timestamp()))
        sign_params.append(('oauth_nonce', generate_nonce()))
        sign_params.append(('oauth_version', OAUTH_VERSION))
        signature_base_string = get_signature_base_string(
            scheme, host, method, path, sign_params)
        sign_params.append(
            ('oauth_signature', self.signer.sign(signature_base_string)))
        return Authorization(sign_params)
