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

import flask
from six import iteritems, string_types


DENY = 'DENY'
SAMEORIGIN = 'SAMEORIGIN'
ALLOW_FROM = 'ALLOW-FROM'
ONE_YEAR_IN_SECS = 31556926

DEFAULT_CSP_POLICY = {
    'default-src': '\'self\'',
}

GOOGLE_CSP_POLICY = {
    # Fonts from fonts.google.com
    'font-src': '\'self\' themes.googleusercontent.com *.gstatic.com',
    # <iframe> based embedding for Maps and Youtube.
    'frame-src': '\'self\' www.google.com www.youtube.com',
    # Assorted Google-hosted Libraries/APIs.
    'script-src': '\'self\' ajax.googleapis.com *.googleanalytics.com '
                  '*.google-analytics.com',
    # Used by generated code from http://www.google.com/fonts
    'style-src': '\'self\' ajax.googleapis.com fonts.googleapis.com '
                 '*.gstatic.com',
    'default-src': '\'self\' *.gstatic.com',
}


class Talisman(object):
    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(
            self,
            app,
            force_https=True,
            force_https_permanent=False,
            frame_options=SAMEORIGIN,
            frame_options_allow_from=None,
            strict_transport_security=True,
            strict_transport_security_max_age=ONE_YEAR_IN_SECS,
            strict_transport_security_include_subdomains=True,
            content_security_policy=DEFAULT_CSP_POLICY,
            session_cookie_secure=True,
            session_cookie_http_only=True):

        self.force_https = force_https
        self.force_https_permanent = force_https_permanent

        self.frame_options = frame_options
        self.frame_options_allow_from = frame_options_allow_from

        self.strict_transport_security = strict_transport_security
        self.strict_transport_security_max_age =\
            strict_transport_security_max_age
        self.strict_transport_security_include_subdomains =\
            strict_transport_security_include_subdomains

        self.content_security_policy = content_security_policy.copy()

        if session_cookie_secure:
            if not app.debug:
                app.config['SESSION_COOKIE_SECURE'] = True

        if session_cookie_http_only:
            app.config['SESSION_COOKIE_HTTPONLY'] = True

        self.app = app
        app.before_request(self._force_https)
        app.after_request(self._after_request)

    def _after_request(self, response):
        self._set_response_headers(response)
        return response

    def _force_https(self):
        """Redirect any non-https requests to https.

        Based largely on flask-sslify.
        """

        criteria = [
            self.app.debug,
            flask.request.is_secure,
            flask.request.headers.get('X-Forwarded-Proto', 'http') == 'https',
        ]

        if self.force_https and not any(criteria):
            if flask.request.url.startswith('http://'):
                url = flask.request.url.replace('http://', 'https://', 1)
                code = 302
                if self.force_https_permanent:
                    code = 301
                r = flask.redirect(url, code=code)
                return r

    def _set_response_headers(self, response):
        self._set_frame_options_headers(response.headers)
        self._set_content_security_policy_headers(response.headers)
        self._set_hsts_headers(response.headers)

    def _set_frame_options_headers(self, headers):
        headers['X-Frame-Options'] = self.frame_options

        if self.frame_options == ALLOW_FROM:
            headers['X-Frame-Options'] += " {}".format(
                self.frame_options_allow_from)

    def _set_content_security_policy_headers(self, headers):
        headers['X-XSS-Protection'] = '1; mode=block'
        headers['X-Content-Type-Options'] = 'nosniff'

        if not self.content_security_policy:
            return

        policies = [
            '{} {}'.format(
                k,
                ' '.join(v) if not isinstance(v, string_types) else v)
            for (k, v)
            in iteritems(self.content_security_policy)
        ]

        value = '; '.join(policies)

        headers['Content-Security-Policy'] = value
        # IE 10-11, Older Firefox.
        headers['X-Content-Security-Policy'] = value

    def _set_hsts_headers(self, headers):
        if not self.strict_transport_security or not flask.request.is_secure:
            return

        value = 'max-age={}'.format(self.strict_transport_security_max_age)

        if self.strict_transport_security_include_subdomains:
            value += '; includeSubDomains'

        value += '; preload'

        headers['Strict-Transport-Security'] = value
