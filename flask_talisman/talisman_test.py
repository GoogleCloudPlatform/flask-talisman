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

from __future__ import absolute_import

import unittest

import flask
from flask_talisman import ALLOW_FROM, DENY, Talisman
from six import iteritems


HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


def hello_world():
    return 'Hello, world'


def with_nonce():
    return flask.render_template_string(
        '<script nonce="{{csp_nonce()}}"></script>'
    )


class TestTalismanExtension(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.talisman = Talisman(self.app)
        self.client = self.app.test_client()

        self.app.route('/')(hello_world)
        self.app.route('/with_nonce')(with_nonce)

    def testDefaults(self):
        # HTTPS request.
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)

        headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'Strict-Transport-Security':
            'max-age=31556926; includeSubDomains',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'default-src \'self\'',
            'X-Content-Security-Policy': 'default-src \'self\'',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
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

    def testLegacyContentSecurityPolicyHeaderOption(self):
        # No header X-Content-Security-Policy present
        self.talisman.legacy_content_security_policy_header = False

        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('X-Content-Security-Policy', response.headers)

        # Header X-Content-Security-Policy present
        self.talisman.legacy_content_security_policy_header = True

        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('X-Content-Security-Policy', response.headers)

    def testHstsOptions(self):
        self.talisman.force_ssl = False

        # No HSTS headers for non-ssl requests
        response = self.client.get('/')
        self.assertNotIn('Strict-Transport-Security', response.headers)

        # Secure request with HSTS off
        self.talisman.strict_transport_security = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('Strict-Transport-Security', response.headers)

        # HSTS back on
        self.talisman.strict_transport_security = True

        # HTTPS request through proxy
        response = self.client.get('/', headers={
            'X-Forwarded-Proto': 'https'
        })
        self.assertIn('Strict-Transport-Security', response.headers)

        # No subdomains
        self.talisman.strict_transport_security_include_subdomains = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn(
            'includeSubDomains', response.headers['Strict-Transport-Security'])

        # Preload
        self.talisman.strict_transport_security_preload = True
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('preload', response.headers['Strict-Transport-Security'])

    def testFrameOptions(self):
        self.talisman.frame_options = DENY
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')

        self.talisman.frame_options = ALLOW_FROM
        self.talisman.frame_options_allow_from = 'example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(
            response.headers['X-Frame-Options'], 'ALLOW-FROM example.com')

        self.talisman.frame_options = None
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('X-Frame-Options', response.headers)

    def testContentSecurityPolicyOptions(self):
        self.talisman.content_security_policy['image-src'] = '*'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertEqual(csp, "default-src 'self'; image-src *")

        self.talisman.content_security_policy['image-src'] = [
            '\'self\'',
            'example.com'
        ]
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertIn('default-src \'self\'', csp)
        self.assertIn('image-src \'self\' example.com', csp)

        # string policy
        self.talisman.content_security_policy = 'default-src \'foo\' spam.eggs'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['Content-Security-Policy'],
                         'default-src \'foo\' spam.eggs')

        # no policy
        self.talisman.content_security_policy = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('Content-Security-Policy', response.headers)

        # string policy at initialization
        app = flask.Flask(__name__)
        Talisman(app, content_security_policy='default-src \'foo\' spam.eggs')
        response = app.test_client().get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn(
            'default-src \'foo\' spam.eggs',
            response.headers['Content-Security-Policy']
        )

    def testContentSecurityPolicyOptionsReport(self):
        # report-only policy
        self.talisman.content_security_policy_report_only = True
        self.talisman.content_security_policy_report_uri = \
            'https://example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('Content-Security-Policy-Report-Only', response.headers)
        self.assertIn(
            'X-Content-Security-Policy-Report-Only', response.headers)
        self.assertIn(
            'report-uri',
            response.headers['Content-Security-Policy-Report-Only']
        )
        self.assertNotIn('Content-Security-Policy', response.headers)
        self.assertNotIn('X-Content-Security-Policy', response.headers)

        override_report_uri = 'https://report-uri.io/'
        self.talisman.content_security_policy = {
            'report-uri': override_report_uri,
        }
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn(
            'Content-Security-Policy-Report-Only', response.headers)
        self.assertIn(
            override_report_uri,
            response.headers['Content-Security-Policy-Report-Only']
        )

        # exception on missing report-uri when report-only
        self.assertRaises(ValueError, Talisman, self.app,
                          content_security_policy_report_only=True)

    def testContentSecurityPolicyNonce(self):
        self.talisman.content_security_policy['script-src'] = "'self'"
        self.talisman.content_security_policy_nonce_in = ['script-src']

        with self.app.test_client() as client:
            response = client.get('/with_nonce',
                                  environ_overrides=HTTPS_ENVIRON)

            csp = response.headers['Content-Security-Policy']

            self.assertIn(
                "script-src 'self' 'nonce-{}'".format(flask.request.csp_nonce),
                csp
            )
            self.assertIn(
                flask.request.csp_nonce,
                response.data.decode("utf-8")
            )

    def testDecorator(self):
        @self.app.route('/nocsp')
        @self.talisman(content_security_policy=None)
        def nocsp():
            return 'Hello, world'

        response = self.client.get('/nocsp', environ_overrides=HTTPS_ENVIRON)
        self.assertNotIn('Content-Security-Policy', response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'SAMEORIGIN')

    def testDecoratorForceHttps(self):
        @self.app.route('/noforcehttps')
        @self.talisman(force_https=False)
        def noforcehttps():
            return 'Hello, world'

        response = self.client.get('/noforcehttps')
        self.assertEqual(response.status_code, 200)

    def testForceFileSave(self):
        self.talisman.force_file_save = True
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('X-Download-Options', response.headers)
        self.assertEqual(response.headers['X-Download-Options'], 'noopen')

    def testBadEndpoint(self):
        response = self.client.get('/bad_endpoint')
        self.assertEqual(response.status_code, 302)
        response = self.client.get('/bad_endpoint',
                                   headers={'X-Forwarded-Proto': 'https'})
        self.assertEqual(response.status_code, 404)

    def testFeaturePolicy(self):
        self.talisman.feature_policy['geolocation'] = '\'none\''
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        feature_policy = response.headers['Feature-Policy']
        self.assertIn('geolocation \'none\'', feature_policy)

        self.talisman.feature_policy['fullscreen'] = '\'self\' example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        feature_policy = response.headers['Feature-Policy']
        self.assertIn('fullscreen \'self\' example.com', feature_policy)

        # string policy at initialization
        app = flask.Flask(__name__)
        Talisman(app, feature_policy='vibrate \'none\'')
        response = app.test_client().get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertIn('vibrate \'none\'', response.headers['Feature-Policy'])
