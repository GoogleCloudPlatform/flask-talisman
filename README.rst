Talisman: HTTP security headers for Flask
=========================================

|Build Status| |Coverage Status| |PyPI Version|

Talisman is a small Flask extension that handles setting HTTP headers
that can help protect against a few common web application security
issues.

The default configuration:

-  Forces all connects to ``https``, unless running with debug enabled.
-  Enables `HTTP Strict Transport
   Security <https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security>`_.
-  Sets Flask's session cookie to ``secure``, so it will never be set if
   you application is somehow accessed via a non-secure connection.
-  Sets Flask's session cookie to ``httponly``, preventing JavaScript
   from being able to access its content. CSRF via Ajax uses a separate
   cookie and should be unaffected.
-  Sets
   `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options>`_
   to ``SAMEORIGIN`` to avoid
   `clickjacking <https://en.wikipedia.org/wiki/Clickjacking>`_.
-  Sets `X-XSS-Protection
   <http://msdn.microsoft.com/en-us/library/dd565647(v=vs.85).aspx>`_ to enable
   a cross site scripting filter for IE/Chrome.
-  Sets `X-Content-Type-Options
   <https://msdn.microsoft.com/library/gg622941(v=vs.85).aspx>`_ to prevents
   content type sniffing for IE >= 9.
-  Sets `X-Download-Options
   <https://msdn.microsoft.com/library/jj542450(v=vs.85).aspx>`_ to prevent
   file downloads opening for IE >= 8.
-  Sets a strict `Content Security
   Policy <https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy>`__
   of ``default-src: 'self'``. This is intended to almost completely
   prevent Cross Site Scripting (XSS) attacks. This is probably the only
   setting that you should reasonably change. See the
   `Content Security Policy`_ section.
-  Sets a strict `Referrer-Policy <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy>`_
   of ``strict-origin-when-cross-origin`` that governs which referrer information should be included with
   requests made.

In addition to Talisman, you **should always use a cross-site request
forgery (CSRF) library**. It's highly recommended to use
`Flask-SeaSurf <https://flask-seasurf.readthedocs.org/en/latest/>`_,
which is based on Django's excellent library.

Installation & Basic Usage
--------------------------

Install via `pip <https://pypi.python.org/pypi/pip>`_:

::

    pip install flask-talisman

After installing, wrap your Flask app with a ``Talisman``:

.. code:: python

    from flask import Flask
    from flask_talisman import Talisman

    app = Flask(__name__)
    Talisman(app)


There is also a full `Example App <https://github.com/GoogleCloudPlatform/flask-talisman/blob/master/example_app>`_.

Options
-------

-  ``force_https``, default ``True``, forces all non-debug connects to
   ``https``.
-  ``force_https_permanent``, default ``False``, uses ``301`` instead of
   ``302`` for ``https`` redirects.
-  ``frame_options``, default ``SAMEORIGIN``, can be ``SAMEORIGIN``,
   ``DENY``, or ``ALLOWFROM``.
-  ``frame_options_allow_from``, default ``None``, a string indicating
   the domains that are allowed to embed the site via iframe.
-  ``strict_transport_security``, default ``True``, whether to send HSTS
   headers.
-  ``strict_transport_security_preload``, default ``False``, enables HSTS
   preloading If you register your application with
   `Google's HSTS preload list <https://hstspreload.appspot.com/>`_,
   Firefox and Chrome will never load your site over a non-secure
   connection.
-  ``strict_transport_security_max_age``, default ``ONE_YEAR_IN_SECS``,
   length of time the browser will respect the HSTS header.
-  ``strict_transport_security_include_subdomains``, default ``True``,
   whether subdomains should also use HSTS.
-  ``content_security_policy``, default ``default-src: 'self'``, see the
   `Content Security Policy`_ section.
-  ``content_security_policy_report_only``, default ``False``, whether to set
   the CSP header as "report-only" (as `Content-Security-Policy-Report-Only`)
   to ease deployment by disabling the policy enforcement by the browser,
   requires passing a value with the ``content_security_policy_report_uri``
   parameter
-  ``content_security_policy_report_uri``, default ``None``, a string
   indicating the report URI used for `CSP violation reports
   <https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_CSP_violation_reports>`_
-  ``referrer_policy``, default ``strict-origin-when-cross-origin``, a string
   that sets the Referrer Policy header to send a full URL when performing a same-origin
   request, only send the origin of the document to an equally secure destination
   (HTTPS->HTTPS), and send no header to a less secure destination (HTTPS->HTTP).
-  ``session_cookie_secure``, default ``True``, set the session cookie
   to ``secure``, preventing it from being sent over plain ``http``.
-  ``session_cookie_http_only``, default ``True``, set the session
   cookie to ``httponly``, preventing it from being read by JavaScript.
-  ``force_file_save``, default ``False``, whether to set the
   ``X-Download-Options`` header to ``noopen`` to prevent IE >= 8 to from
   opening file downloads directly and only save them instead

Per-view options
~~~~~~~~~~~~~~~~

Sometimes you want to change the policy for a specific view. The
``force_https``, ``frame_options``, ``frame_options_allow_from``, and
``content_security_policy`` options can be changed on a per-view basis.

.. code:: python

    from flask import Flask
    from flask_talisman import Talisman, ALLOW_FROM

    app = Flask(__name__)
    talisman = Talisman(app)

    @app.route('/normal')
    def normal():
        return 'Normal'

    @app.route('/embeddable')
    @talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
    def embeddable():
        return 'Embeddable'

Content Security Policy
-----------------------

The default content security policy is extremely strict and will
prevent loading any resources that are not in the same domain as the
application. Most web applications will need to change this policy.

A slightly more permissive policy is available at
``flask_talisman.GOOGLE_CSP_POLICY``, which allows loading Google-hosted JS
libraries, fonts, and embeding media from YouTube and Maps.

You can and should create your own policy to suit your site's needs.
Here's a few examples adapted from
`MDN <https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_Content_Security_Policy>`_:

Example 1
~~~~~~~~~

This is the default policy. A web site administrator wants all content
to come from the site's own origin (this excludes subdomains.)

.. code:: python

    csp = {
        'default-src': '\'self\''
    }

Example 2
~~~~~~~~~

A web site administrator wants to allow content from a trusted domain
and all its subdomains (it doesn't have to be the same domain that the
CSP is set on.)

.. code:: python

    csp = {
        'default-src': [
            '\'self\'',
            '*.trusted.com'
        ]
    }

Example 3
~~~~~~~~~

A web site administrator wants to allow users of a web application to
include images from any origin in their own content, but to restrict
audio or video media to trusted providers, and all scripts only to a
specific server that hosts trusted code.

.. code:: python

    csp = {
        'default-src': '\'self\'',
        'image-src': '*',
        'media-src': [
            'media1.com',
            'media2.com',
        ],
        'script-src': 'userscripts.example.com'
    }

In this example content is only permitted from the document's origin
with the following exceptions:

-  Images may loaded from anywhere (note the ``*`` wildcard).
-  Media is only allowed from media1.com and media2.com (and not from
   subdomains of those sites).
-  Executable script is only allowed from userscripts.example.com.

Example 4
~~~~~~~~~

A web site administrator for an online banking site wants to ensure that
all its content is loaded using SSL, in order to prevent attackers from
eavesdropping on requests.

.. code:: python

    csp = {
        'default-src': 'https://onlinebanking.jumbobank.com'
    }

The server only permits access to documents being loaded specifically
over HTTPS through the single origin onlinebanking.jumbobank.com.

Example 5
~~~~~~~~~

A web site administrator of a web mail site wants to allow HTML in
email, as well as images loaded from anywhere, but not JavaScript or
other potentially dangerous content.

.. code:: python

    csp = {
        'default-src': [
            '\'self\'',
            '*.mailsite.com',
        ],
        'img-src': '*'
    }

Note that this example doesn't specify a ``script-src``; with the
example CSP, this site uses the setting specified by the ``default-src``
directive, which means that scripts can be loaded only from the
originating server.

Disclaimer
----------

This is not an official Google product, experimental or otherwise.

There is no silver bullet for web application security. Talisman can
help, but security is more than just setting a few headers. Any
public-facing web application should have a comprehensive approach to
security.


Contributing changes
--------------------

-  See `CONTRIBUTING.md`_

Licensing
---------

- Apache 2.0 - See `LICENSE`_

.. _LICENSE: https://github.com/GoogleCloudPlatform/flask-talisman/blob/master/LICENSE
.. _CONTRIBUTING.md: https://github.com/GoogleCloudPlatform/flask-talisman/blob/master/CONTRIBUTING.md
.. |Build Status| image:: https://travis-ci.org/GoogleCloudPlatform/flask-talisman.svg
   :target: https://travis-ci.org/GoogleCloudPlatform/flask-talisman
.. |Coverage Status| image:: https://coveralls.io/repos/GoogleCloudPlatform/flask-talisman/badge.svg
   :target: https://coveralls.io/r/GoogleCloudPlatform/flask-talisman
.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-talisman.svg
   :target: https://pypi.python.org/pypi/flask-talisman
