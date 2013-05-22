import hmac
from urllib import quote
from urlparse import urlparse
from urlparse import parse_qsl
from binascii import b2a_base64
from urllib import unquote_plus
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1


class ValidationException(Exception):
    pass


def url_encode(params):
    if type(params) in (list, tuple):
        pairs = []
        for k, v in params:
            pairs.append('%s=%s' % (url_encode(k), url_encode(v)))
        return '&'.join(pairs)

    if type(params) == dict:
        property_list = []
        for key, value in params.iteritems():
            if type(value) in (list, tuple):
                for sub_value in value:
                    property_list.append((key, sub_value))
            else:
                property_list.append((key, value))
        return url_encode(property_list)

    return quote(str(params).encode('utf-8'), safe='~')


def hmac_sha1_signer(signature_base_string, consumer_secret, token_secret):
    """Create a HMAC-SHA1 signature."""
    key = '%s&%s' % (url_encode(consumer_secret), url_encode(token_secret))
    signature = hmac.new(key, signature_base_string, sha1)
    return b2a_base64(signature.digest())[:-1]


def plaintext_signer(signature_base_string, consumer_secret, token_secret):
    """Create an insecure PLAINTEXT signature."""
    return '%s&%s' % (url_encode(consumer_secret), url_encode(token_secret))


class SignatureException(Exception):
    """Exception raised whenever an issue with signing occurs."""
    pass


class Signer(object):
    """Main unit of logic used to perform OAuth signatures."""

    def __init__(
            self, scheme, method, host, port, uri, headers=None, body=''):
        """Set the object up based on all of the HTTP request parts."""
        if headers is None:
            headers = {}
        parsed_uri = urlparse(uri)

        self.scheme = scheme
        self.method = method
        # sometimes the host is given in the form 192.168.2.1:8000
        self.host = ':' in host and host.split(':')[0] or host
        self.port = port
        self.path = parsed_uri[2] and parsed_uri[2] or '/'
        self.headers = headers
        self.body = body
        self.realm = ''
        self.params = parse_qsl(parsed_uri[4])
        self.auth_header_params = {}
        self.signature_generators = {}
        self._init_default_callbacks()

        for key, value in headers.iteritems():
            key = key.lower()
            if key == 'content-type' and \
                    'application/x-www-form-urlencoded' in value:
                body_params = parse_qsl(self.body)
                self.params.extend(body_params)
            elif key == 'authorization':
                self._consume_oauth_header(value.strip())

    def _consume_oauth_header(self, value):
        """Parse the OAuth header, if it is properly formatted."""
        try:
            value.index('OAuth ')
        except ValueError:
            return []

        value = unquote_plus(value[6:])
        for key, value in parse_header(value):
            if key == 'realm':
                self.realm = value
            else:
                self.auth_header_params[key] = value

    def get_param(self, name, default=None):
        """
        Get a parameter first from the OAuth header, then from the
        other parameters.
        """
        if name in self.auth_header_params:
            return self.auth_header_params[name]
        for key, value in self.params:
            if key == name:
                return value
        return default

    def make_oauth_header(self):
        """
        Generate the actual header that will be used for OAuth.
        """
        params = {
            'oauth_callback':         self.get_param('oauth_callback'),
            'oauth_consumer_key':     self.get_param('oauth_consumer_key'),
            'oauth_nonce':            self.get_param('oauth_nonce'),
            'oauth_signature':        self.get_signature(False),
            'oauth_signature_method': self.get_param('oauth_signature_method'),
            'oauth_timestamp':        self.get_param('oauth_timestamp'),
            'oauth_token':            self.get_param('oauth_token'),
            'oauth_version':          self.get_param('oauth_version'),
        }

        if not params['oauth_callback']: # truthiness test
            del params['oauth_callback']
        if not params['oauth_token']: # truthiness test
            del params['oauth_token']

        property_list = list(sorted(params.iteritems()))
        property_list.insert(0, ('realm', self.realm))
        return 'OAuth %s' % ','.join(
            '%s="%s"' % (k, url_encode(v)) for k, v in property_list)

    def _get_base_string_uri(self):
        parts = [self.scheme, '://', self.host.lower()]
        non_standard_http_port = self.scheme == 'http' and self.port != 80
        non_standard_https_port = self.scheme == 'https' and self.port != 443
        if non_standard_http_port or non_standard_https_port:
            parts.append(':')
            parts.append(str(self.port))
        parts.append(self.path)
        return ''.join(parts)

    def _get_normalized_request_params(self):
        sign_params = []
        input_params = self.params + self.auth_header_params.items()
        for key, value in input_params:
            if key == 'oauth_signature':
                continue
            sign_params.append((url_encode(key), url_encode(value)))
        sign_params.sort(key=lambda x: x[1])
        sign_params.sort(key=lambda x: x[0])
        return '&'.join('%s=%s' % (k, v) for k, v in sign_params)

    def _get_signature_base_string(self):
        return '%s&%s&%s' % (
            self.method.upper(),
            url_encode(self._get_base_string_uri()),
            url_encode(self._get_normalized_request_params()))

    def get_signature(self, validate_timestamp_and_nonce=None):
        if validate_timestamp_and_nonce is None:
            validate_timestamp_and_nonce = True

        if validate_timestamp_and_nonce:
            are_timestamp_and_nonce_valid = self.timestamp_and_nonce_validator(
                int(self.get_param('oauth_timestamp')),
                self.get_param('oauth_nonce'),
                self.get_param('oauth_consumer_key'))
            if not are_timestamp_and_nonce_valid:
                raise ValidationException('Invalid nonce/timestamp combination')

        consumer_secret = self.consumer_secret_finder(
            self.get_param('oauth_consumer_key'))
        token_secret = self.token_secret_finder(
            self.get_param('oauth_consumer_key'),
            self.get_param('oauth_token'))

        signature_callback = self.get_signature_generator(
            self.get_param('oauth_signature_method', 'hmac-sha1'))
        signature = signature_callback(
            self._get_signature_base_string(),
            consumer_secret,
            token_secret)
        return signature

    @property
    def scheme(self):
        """Getter for scheme."""
        return self._scheme

    @scheme.setter
    def scheme(self, value):
        """Setter for scheme."""
        self._scheme = value

    @property
    def method(self):
        """Getter for method."""
        return self._method

    @method.setter
    def method(self, value):
        """Setter for method."""
        self._method = value

    @property
    def host(self):
        """Getter for host."""
        return self._host

    @host.setter
    def host(self, value):
        """Setter for host."""
        self._host = value

    @property
    def port(self):
        """Getter for port."""
        return self._port

    @port.setter
    def port(self, value):
        """Setter for port."""
        self._port = int(value)

    @property
    def path(self):
        """Getter for path."""
        return self._path

    @path.setter
    def path(self, value):
        """Setter for path."""
        self._path = value

    @property
    def headers(self):
        """Getter for headers."""
        return self._headers

    @headers.setter
    def headers(self, value):
        """Setter for headers."""
        self._headers = value

    @property
    def body(self):
        """Getter for body."""
        return self._body

    @body.setter
    def body(self, value):
        """Setter for body."""
        self._body = value

    @property
    def realm(self):
        """Getter for realm."""
        return self._realm

    @realm.setter
    def realm(self, value):
        """Setter for realm."""
        self._realm = value

    @property
    def params(self):
        """Getter for params."""
        return self._params

    @params.setter
    def params(self, value):
        """Setter for params."""
        self._params = value

    @property
    def auth_header_params(self):
        """Getter for auth_header_params."""
        return self._auth_header_params

    @auth_header_params.setter
    def auth_header_params(self, value):
        """Setter for auth_header_params."""
        self._auth_header_params = value

    @property
    def timestamp_and_nonce_validator(self):
        """Getter for timestamp_and_nonce_validator."""
        return self._timestamp_and_nonce_validator

    @timestamp_and_nonce_validator.setter
    def timestamp_and_nonce_validator(self, value):
        """Setter for timestamp_and_nonce_validator."""
        self._timestamp_and_nonce_validator = value

    @property
    def consumer_secret_finder(self):
        """Getter for consumer_secret_finder."""
        return self._consumer_secret_finder

    @consumer_secret_finder.setter
    def consumer_secret_finder(self, value):
        """Setter for consumer_secret_finder."""
        self._consumer_secret_finder = value

    @property
    def token_secret_finder(self):
        """Getter for token_secret_finder."""
        return self._token_secret_finder

    @token_secret_finder.setter
    def token_secret_finder(self, value):
        """Setter for token_secret_finder."""
        self._token_secret_finder = value

    @property
    def signature_generators(self):
        """Getter for signature_generators."""
        return self._signature_generators

    @signature_generators.setter
    def signature_generators(self, value):
        """Setter for signature_generators."""
        self._signature_generators = value

    def register_signature_generator(self, signature_method, callback):
        """Register a signature callback using the given name."""
        signature_method = signature_method.lower()
        self.signature_generators[signature_method] = callback
        return self

    def get_signature_generator(self, signature_method):
        """Get a named callback to generate signatures with."""
        signature_method = signature_method.lower()
        if signature_method not in self.signature_generators:
            raise SignatureException(
                'No callback registered for OAuth Signature Method: %s' % \
                signature_method)
        return self.signature_generators[signature_method]

    def _init_default_callbacks(self):
        """Set up default logic for signature generators and callbacks."""
        self.timestamp_and_nonce_validator = \
            lambda timestamp, nonce, oauth_consumer_key: True
        self.register_signature_generator('hmac-sha1', hmac_sha1_signer)
        self.register_signature_generator('plaintext', plaintext_signer)
        self.consumer_secret_finder = lambda consumer: ''
        self.token_secret_finder = lambda consumer, token: ''


class LexerError(Exception):
    pass


class ParserError(Exception):
    pass


def parse_header(value):
    """
    Parses the OAuth header--the grammar is so simple that the
    recursive descent has been flattened into a single function.

    BNF Grammar:
    <header>  ::= <pair>
                | <pair> T_COMMA <header>
    <pair>    ::= <literal> T_OP_EQ <literal>
    <literal> ::= T_TOKEN
                | T_QDTEXT
    """
    tokens = lex_header(value)
    pairs = []
    while True:
        pos, token_name, token_value = tokens.next()
        if token_name == 'T_END':
            break
        if token_name not in ('T_QDTEXT', 'T_TOKEN'):
            raise ParserError('unexpected token at position %d' % pos)
        pair_key = token_value

        pos, token_name, token_value = tokens.next()
        if token_name != 'T_OP_EQ':
            raise ParserError('expected = at position %d, got %s' % (
                pos, token_value))

        pos, token_name, token_value = tokens.next()
        if token_name == 'T_END':
            pairs.append((pair_key, ''))
            break

        if token_name in ('T_QDTEXT', 'T_TOKEN'):
            pairs.append((pair_key, token_value))
            pos, token_name, token_value = tokens.next()
            if token_name == 'T_END':
                break
            if token_name != 'T_COMMA':
                raise ParserError('unexpected token at position %d' % pos)
        elif token_name == 'T_COMMA':
            pairs.append((pair_key, ''))
        else:
            raise ParserError('unexpected token at position %d' % pos)

    return pairs


def lex_header(value):
    lex_table = (
        lex_header_whitespace,
        lex_header_comma,
        lex_header_op_eq,
        lex_header_qdtext,
        lex_header_token)
    pos = 0
    while pos < len(value):
        iteration_found_token = False
        for lex_func in lex_table:
            if iteration_found_token:
                break
            result = lex_func(value, pos)
            if result is not None:
                iteration_found_token = True
                pos = result[0]
                if result[1] is not None:
                    yield result
        if not iteration_found_token:
            raise LexerError('unknown token at position %d' % pos)
    yield None, 'T_END', None


def lex_header_comma(value, pos):
    if value[pos] != ',':
        return None
    return pos + 1, 'T_COMMA', ','


def lex_header_op_eq(value, pos):
    if value[pos] != '=':
        return None
    return pos + 1, 'T_OP_EQ', '='


def lex_header_qdtext(value, pos):
    if value[pos] != '"':
        return None
    parts = []
    last_was_backslash = False
    for i in range(pos + 1, len(value)):
        if value[i] == '\\' and not last_was_backslash:
            last_was_backslash = True
        elif last_was_backslash:
            parts.append(value[i])
            last_was_backslash = False
        elif value[i] == '"':
            return i + 1, 'T_QDTEXT', ''.join(parts)
        else:
            parts.append(value[i])
    raise LexerError('unterminated quoted string at position %d' % pos)


HEADER_SEPARATORS = (
    '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']',
    '?', '=', '{', '}', ' ', '\t',
)


def lex_header_token(value, pos):
    if value[pos] in HEADER_SEPARATORS:
        return None
    parts = []
    for i in range(pos, len(value)):
        if value[i] in HEADER_SEPARATORS:
            return i, 'T_TOKEN', ''.join(parts)
        parts.append(value[i])
    return len(value), 'T_TOKEN', ''.join(parts)


def lex_header_whitespace(value, pos):
    if value[pos] in (' ', '\t'):
        return pos + 1, None, None
