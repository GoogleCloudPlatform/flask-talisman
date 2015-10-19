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

from functools import wraps

import flask
from six import iteritems, string_types
from werkzeug.local import Local


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

_sentinel = object()


class Talisman(object):
    """
    Talisman is a Flask extension for HTTP security headers.
    """

    def __init__(self, app=None, **kwargs):
        if app is not None:
            self.init_app(app, **kwargs)

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
        """
        Initialization.

        Args:
            app: A Flask application.
            force_https: Redirects non-http requests to https, disabled in
                debug mode.
            force_https_permanent: Uses 301 instead of 302 redirects.
            frame_options: Sets the X-Frame-Options header, defaults to
                SAMEORIGIN.
            frame_options_allow_from: Used when frame_options is set to
                ALLOW_FROM and is a string of domains to allow frame embedding.
            strict_transport_security: Sets HSTS headers.
            strict_transport_security_max_age: How long HSTS headers are
                honored by the browser.
            strict_transport_security_include_subdomain: Whether to include
                all subdomains when setting HSTS.
            content_security_policy: A string or dictionary describing the
                content security policy for the response.
            session_cookie_secure: Forces the session cookie to only be sent
                over https. Disabled in debug mode.
            session_cookie_http_only: Prevents JavaScript from reading the
                session cookie.

        See README.rst for a detailed description of each option.
        """

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

        self.session_cookie_secure = session_cookie_secure

        if session_cookie_http_only:
            app.config['SESSION_COOKIE_HTTPONLY'] = True

        self.app = app
        self.local_options = Local()

        app.before_request(self._update_local_options)
        app.before_request(self._force_https)
        app.after_request(self._set_response_headers)

    def _update_local_options(
            self,
            frame_options=_sentinel,
            frame_options_allow_from=_sentinel,
            content_security_policy=_sentinel):
        """Updates view-local options with defaults or specified values."""
        setattr(self.local_options, 'frame_options',
                frame_options if frame_options is not _sentinel
                else self.frame_options)
        setattr(self.local_options, 'frame_options_allow_from',
                frame_options_allow_from if frame_options_allow_from
                is not _sentinel else self.frame_options_allow_from)
        setattr(self.local_options, 'content_security_policy',
                content_security_policy if content_security_policy
                is not _sentinel else self.content_security_policy)

    def _force_https(self):
        """Redirect any non-https requests to https.

        Based largely on flask-sslify.
        """

        if self.session_cookie_secure:
            if not self.app.debug:
                self.app.config['SESSION_COOKIE_SECURE'] = True

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
        """Applies all configured headers to the given response."""
        self._set_frame_options_headers(response.headers)
        self._set_content_security_policy_headers(response.headers)
        self._set_hsts_headers(response.headers)
        return response

    def _set_frame_options_headers(self, headers):
        headers['X-Frame-Options'] = self.local_options.frame_options

        if self.local_options.frame_options == ALLOW_FROM:
            headers['X-Frame-Options'] += " {}".format(
                self.local_options.frame_options_allow_from)

    def _set_content_security_policy_headers(self, headers):
        headers['X-XSS-Protection'] = '1; mode=block'
        headers['X-Content-Type-Options'] = 'nosniff'

        if not self.local_options.content_security_policy:
            return

        policy = self.local_options.content_security_policy

        if not isinstance(policy, string_types):
            policies = [
                '{} {}'.format(
                    k,
                    ' '.join(v) if not isinstance(v, string_types) else v)
                for (k, v)
                in iteritems(policy)
            ]

            policy = '; '.join(policies)

        headers['Content-Security-Policy'] = policy
        # IE 10-11, Older Firefox.
        headers['X-Content-Security-Policy'] = policy

    def _set_hsts_headers(self, headers):
        if not self.strict_transport_security or not flask.request.is_secure:
            return

        value = 'max-age={}'.format(self.strict_transport_security_max_age)

        if self.strict_transport_security_include_subdomains:
            value += '; includeSubDomains'

        value += '; preload'

        headers['Strict-Transport-Security'] = value

    def __call__(
            self,
            frame_options=_sentinel,
            frame_options_allow_from=_sentinel,
            content_security_policy=_sentinel):
        """Use talisman as a decorator to configure options for a particular
        view.

        Only frame_options, frame_options_allow_from, and
        content_security_policy can be set on a per-view basis.

        Example:

            app = Flask(__name__)
            talisman = Talisman(app)

            @app.route('/normal')
            def normal():
                return 'Normal'

            @app.route('/embeddable')
            @talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
            def embeddable():
                return 'Embeddable'
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                self._update_local_options(
                    frame_options=frame_options,
                    frame_options_allow_from=frame_options_allow_from,
                    content_security_policy=content_security_policy)
                return f(*args, **kwargs)
            return decorated_function
        return decorator
