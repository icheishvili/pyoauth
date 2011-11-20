iOAuth
======

iOAuth is a Python library for dealing with OAuth.

It gives you, the developer, full control over everything that is
going on. That means you can:

  * Write logic to re-use HTTP connections and perform much better
  * Control exactly what parameters get sent and how
  * Support out-of-band verifier codes
  * Use Python's HTTP facilities to their fullest extend (for example,
    file uploading)

Also, the code behind the library tries to be simple and easy to
understand, while refering to the relevant sections in the OAuth
specification (http://tools.ietf.org/html/rfc5849). So, unlike other
libraries, this is one that you can follow along with and learn more
about OAuth from.

Twitter Example
---------------
Here is an example of interfacing with Twitter (make you to grab your
own application credentials first).

    from ioauth import Consumer
    from ioauth import token_from_string
    from ioauth import parse_path, parse_host, parse_port, parse_qs_real
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

More Examples
-------------
In the examples directory, there are more examples of how to use the
library. Given that I like Beatport, I have included full examples of
how to use both types of OAuth with Beatport's public OAuth API.

License
-------
Copyright (c) 2011, Ilia Cheishvili
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
  * Neither the name of the organization nor the
    names of its contributors may be used to endorse or promote products
    derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL ILIA CHEISHVILI BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.