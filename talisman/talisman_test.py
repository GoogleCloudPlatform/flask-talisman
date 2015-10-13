# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

import flask
from six import iteritems
from talisman import ALLOW_FROM, DENY, Talisman


HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


class TestTalismanExtension(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.talisman = Talisman(self.app)
        self.client = self.app.test_client()

        self.app.route('/')(lambda: 'Hello, world')

    def testDefaults(self):
        # HTTPS request.
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)

        headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'Strict-Transport-Security':
            'max-age=31556926; includeSubDomains; preload',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'default-src \'self\'',
            'X-Content-Security-Policy': 'default-src \'self\''
        }

        for key, value in iteritems(headers):
            self.assertEqual(response.headers.get(key), value)

    def testForceSslOptionOptions(self):
        # HTTP request from Proxy
        response = self.client.get('/', headers={
            'X-Forwarded-Proto': 'https'
        })
        self.assertEqual(response.status_code, 200)

        # HTTP Request, should be upgraded to https
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('https://'))

        # Permanent redirects
        self.talisman.force_https_permanent = True
        response = self.client.get('/')
        self.assertEqual(response.status_code, 301)

        # Disable forced ssl, should allow the request.
        self.talisman.force_https = False
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testHstsOptions(self):
        self.talisman.force_ssl = False

        # No HSTS headers for non-ssl requests
        response = self.client.get('/')
        self.assertTrue('Strict-Transport-Security' not in response.headers)

        # Secure request with HSTS off
        self.talisman.strict_transport_security = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue('Strict-Transport-Security' not in response.headers)

        # No subdomains
        self.talisman.strict_transport_security = True
        self.talisman.strict_transport_security_include_subdomains = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue(
            'includeSubDomains' not in
            response.headers['Strict-Transport-Security'])

    def testFrameOptions(self):
        self.talisman.frame_options = DENY
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')

        self.talisman.frame_options = ALLOW_FROM
        self.talisman.frame_options_allow_from = 'example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(
            response.headers['X-Frame-Options'], 'ALLOW-FROM example.com')

    def testContentSecurityPolicyOptions(self):
        self.talisman.content_security_policy['image-src'] = '*'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['Content-Security-Policy'],
                         'default-src \'self\'; image-src *')

        self.talisman.content_security_policy['image-src'] = [
            '\'self\'',
            'example.com'
        ]
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertTrue('default-src \'self\'' in csp)
        self.assertTrue('image-src \'self\' example.com' in csp)

        # sting policy
        self.talisman.content_security_policy = 'default-src example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['Content-Security-Policy'],
                         'default-src example.com')

        # no policy
        self.talisman.content_security_policy = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue('Content-Security-Policy' not in response.headers)

    def testDecorator(self):

        @self.app.route('/nocsp')
        @self.talisman(content_security_policy=None)
        def nocsp():
            return 'Hello, world'

        response = self.client.get('/nocsp', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue('Content-Security-Policy' not in response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'SAMEORIGIN')
