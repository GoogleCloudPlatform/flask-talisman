Talisman: HTTP security headers for Flask
=========================================

|PyPI Version|

Talisman is a small Flask extension that handles setting HTTP headers
that can help protect against a few common web application security
issues.

The default configuration:

-  Forces all connects to ``https``, unless running with debug enabled.
-  Enables `HTTP Strict Transport
   Security <https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security>`_.
-  Sets Flask's session cookie to ``secure``, so it will never be set if
   your application is somehow accessed via a non-secure connection.
-  Sets Flask's session cookie to ``httponly``, preventing JavaScript
   from being able to access its content. CSRF via Ajax uses a separate
   cookie and should be unaffected.
-  Sets
   `X-Frame-Options <https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options>`_
   to ``SAMEORIGIN`` to avoid
   `clickjacking <https://en.wikipedia.org/wiki/Clickjacking>`_.
-  Sets `X-XSS-Protection
   <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection>`_
   to enable a cross site scripting filter for IE and Safari (note Chrome has
   removed this and Firefox never supported it).
-  Sets `X-Content-Type-Options
   <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options>`_
   to prevent content type sniffing.
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


There is also a full `Example App <https://github.com/wntrblm/flask-talisman/blob/master/example_app>`_.

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
-  ``content_security_policy_nonce_in``, default ``[]``. Adds a per-request nonce
   value to the flask request object and also to the specified CSP header section.
   I.e. ``['script-src', 'style-src']``
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
-  ``feature_policy``, default ``{}``, see the `Feature Policy`_ section.
-  ``permissions_policy``, default ``{}``, see the `Permissions Policy`_ section.
-  ``document_policy``, default ``{}``, see the `Document Policy`_ section.

-  ``session_cookie_secure``, default ``True``, set the session cookie
   to ``secure``, preventing it from being sent over plain ``http``.
-  ``session_cookie_http_only``, default ``True``, set the session
   cookie to ``httponly``, preventing it from being read by JavaScript.
-  ``force_file_save``, default ``False``, whether to set the
   `X-Download-Options <https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/jj542450(v=vs.85)?redirectedfrom=MSDN>`_
   header to ``noopen`` to prevent IE >= 8 to from opening file downloads
   directly and only save them instead.

Per-view options
~~~~~~~~~~~~~~~~

Sometimes you want to change the policy for a specific view. The
``force_https``, ``frame_options``, ``frame_options_allow_from``,
`content_security_policy``, ``feature_policy``, ``permissions_policy``
and ``document_policy`` options can be changed on a per-view basis.

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
    talisman = Talisman(app, content_security_policy=csp)

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
        'img-src': '*',
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

Example 6
~~~~~~~~~

A web site administrator wants to allow embedded scripts (which might
be generated dynamicially).

.. code:: python

    csp = {
        'default-src': '\'self\'',
        'script-src': '\'self\'',
    }
    talisman = Talisman(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src']
    )

The nonce needs to be added to the script tag in the template:

.. code:: html

    <script nonce="{{ csp_nonce() }}">
        //...
    </script>

Note that the CSP directive (`script-src` in the example) to which the `nonce-...`
source should be added needs to be defined explicitly.

Example 7
~~~~~~~~~

A web site adminstrator wants to override the CSP directives via an
environment variable which doesn't support specifying the policy as
a Python dictionary, e.g.:

.. code:: bash

    export CSP_DIRECTIVES="default-src 'self'; image-src *"
    python app.py

Then in the app code you can read the CSP directives from the environment:

.. code:: python

    import os
    from flask_talisman import Talisman, DEFAULT_CSP_POLICY

    talisman = Talisman(
        app,
        content_security_policy=os.environ.get("CSP_DIRECTIVES", DEFAULT_CSP_POLICY),
    )

As you can see above the policy can be defined simply just like the official
specification requires the HTTP header to be set: As a semicolon separated
list of individual CSP directives.

Permissions Policy
------------------

Feature Policy has been split into Permissions Policy and Document Policy but
at this writing `browser support of Permissions Policy is very limited <https://caniuse.com/permissions-policy>`_,
and it is recommended to still set the ``Feature-Policy`` HTTP Header.
Permission Policy support is included in Talisman for when this becomes more
widely supported.

The default permissions policy is empty, as this is the default expected behaviour.
Note that the `Permission Policy is still an Editor's Draft <https://www.w3.org/TR/permissions-policy/>`_.

Permission Policy can be set either using a dictionary, or using a string.

Geolocation and Microphone Example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Disable access to Geolocation interface and Microphone using dictionary syntax

.. code:: python
    permission_policy = {
        'geolocation': '()',
        'microphone': '()'
    }
    talisman = Talisman(app, permission_policy=permission_policy)
Disable access to Geolocation interface and Microphone using string syntax

.. code:: python
    permission_policy = 'geolocation=(), microphone=()'
    talisman = Talisman(app, permission_policy=permission_policy)
Document Policy
---------------

Feature Policy has been split into Permissions Policy and Document Policy but
at this writing `browser support of Document Policy is very limited <https://caniuse.com/document-policy>`_,
and it is recommended to still set the ``Feature-Policy`` HTTP Header.
Document Policy support is included in Talisman for when this becomes more
widely supported.

The default permissions policy is empty, as this is the default expected behaviour.
Note that the `Document Policy is still an Editors Draft <https://w3c.github.io/webappsec-feature-policy/document-policy.html>`_.

Document Policy can be set either using a dictionary, or using a string.

Oversized-Images Example
~~~~~~~~~~~~~~~~~~~~~~~~

Forbid oversized-images using dictionary syntax:

.. code:: python
    document_policy = {
        'oversized-images': '?0'
    }
    talisman = Talisman(app, document_policy=document_policy)
Forbid oversized-images using string syntax:

.. code:: python
    document_policy = 'oversized-images=?0'
    talisman = Talisman(app, document_policy=document_policy)

Feature Policy
--------------

Note: Feature Policy has largely been `renamed Permissions Policy <https://github.com/w3c/webappsec-feature-policy/issues/359>`_
in the latest draft and some features are likely to move to Document Policy.
At this writing, most browsers support the ``Feature-Policy`` HTTP Header name._
See the `Permissions Policy`_ and `Document Policy`_ sections should you wish
to set these.

The default feature policy is empty, as this is the default expected behaviour.
Note that the Feature Policy is still a `draft https://wicg.github.io/feature-policy/`
but is `supported in some form in most browsers
<https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy#Browser_compatibility>`_.

Geolocation Example
~~~~~~~~~~~~~~~~~~~

Disable access to Geolocation interface.

.. code:: python

    feature_policy = {
        'geolocation': '\'none\''
    }
    talisman = Talisman(app, feature_policy=feature_policy)

Disclaimer
----------

This code originated at Google, but is not an official Google product,
experimental or otherwise. It was forked on June 6th, 2021 from the
unmaintained GoogleCloudPlatform/flask-talisman.

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

.. _LICENSE: https://github.com/wntrblm/flask-talisman/blob/master/LICENSE
.. _CONTRIBUTING.md: https://github.com/wntrblm/flask-talisman/blob/master/CONTRIBUTING.md
.. |PyPI Version| image:: https://img.shields.io/pypi/v/flask-talisman.svg
   :target: https://pypi.python.org/pypi/flask-talisman
