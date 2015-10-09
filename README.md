# Talisman for Flask

Talisman is a small Flask extension that configures a few simple countermeasures
against common web application security issues.

The default configuration:

* Forces all connects to `https`, unless running with debug enabled.
* Enables [HTTP Strict Transport Security](https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security).
* Enables HSTS preloading. If you register your application with [Google's HSTS preload list](https://hstspreload.appspot.com/), Firefox and Chrome will never load your site over a non-secure connection.
* Sets Flask's session cookie to `secure`, so it will never be set if you application is somehow accessed via a non-secure connection.
* Sets Flask's session cookie to `httponly`, preventing JavaScript from being able to access its content. CSRF via Ajax uses a separate cookie and should be unaffected.
* Sets [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/X-Frame-Options) to `SAMEORIGIN` to avoid [clickjacking](https://en.wikipedia.org/wiki/Clickjacking).
* Sets a strict [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy) of `default-src: 'self'`. This is intended to almost completely prevent Cross Site Scripting (XSS) attacks. This is probably the only setting that you should reasonably change. See the [section below](#content-security-policy) on configuring this.

In addition to Talisman, you **should always use a cross-site request forgery (CSRF) library**. I highly recommend [Flask-SeaSurf](https://flask-seasurf.readthedocs.org/en/latest/), which is based on Django's excellent library.

## Basic Usage

```python
from flask import Flask
from talisman import Talisman

app = Flask(__name__)
Talisman(app)
```

## Options

* `force_https`, default `True`, forces all non-debug connects to `https`.
* `force_https_permanent`, default `False`, uses `301` instead of `302` for `https` redirects.
* `frame_options`, default `SAMEORIGIN`, can be `SAMEORIGIN`, `DENY`, or `ALLOWFROM`.
* `frame_options_allow_from`, default `None`, a string indicating the domains that arrow allowed to embed the site via iframe.
* `strict_transport_security`, default `True`, whether to send HSTS headers.
* `strict_transport_security_max_age`, default `ONE_YEAR_IN_SECS`, length of time the browser will respect the HSTS header.
* `strict_transport_security_include_subdomains`, default `True`, whether subdomains should also use HSTS.
* `content_security_policy`, default `default-src: 'self'`, see the [section below](#content-security-policy).
* `session_cookie_secure`, default `True`, set the session cookie to `secure`, preventing it from being sent over plain `http`.
* `session_cookie_http_only`, default `True`, set the session cookie to `httponly`, preventing it from being read by JavaScript.

## Content Security Policy

The default content security policy is extremely strict, and will prevent
loading any resources that are not in the same domain as the application.

A slightly more permissive policy is available at `talisman.GOOGLE_CSP_POLICY`,
which allows loading Google-hosted JS libraries, fonts, and embeding media from
YouTube and Maps.

You can and should create your own policy to suit your site's needs. Here's a
few examples adapted from [MDN](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Using_Content_Security_Policy):

### Example 1

This is the default policy. A web site administrator wants all content to come
from the site's own origin (this excludes subdomains.)

```python
csp = {
    'default-src': '\'self\''
}
```

### Example 2

A web site administrator wants to allow content from a trusted domain and all its subdomains (it doesn't have to be the same domain that the CSP is set on.)

```python
csp = {
    'default-src': [
        '\'self\'',
        '*.trusted.com'
    ]
}
```

### Example 3

A web site administrator wants to allow users of a web application to include images from any origin in their own content, but to restrict audio or video media to trusted providers, and all scripts only to a specific server that hosts trusted code.

```python
csp = {
    'default-src': '\'self\'',
    'image-src': '*',
    'media-src': [
        'media1.com',
        'media2.com',
    ],
    'script-src': 'userscripts.example.com'
}
```

Here, by default, content is only permitted from the document's origin, with the following exceptions:

* Images may loaded from anywhere (note the `*` wildcard).
* Media is only allowed from media1.com and media2.com (and not from subdomains of those sites).
* Executable script is only allowed from userscripts.example.com.

### Example 4

A web site administrator for an online banking site wants to ensure that all its content is loaded using SSL, in order to prevent attackers from eavesdropping on requests.

```python
csp = {
    'default-src': 'https://onlinebanking.jumbobank.com'
}
```

The server only permits access to documents being loaded specifically over HTTPS through the single origin onlinebanking.jumbobank.com.

### Example 5

A web site administrator of a web mail site wants to allow HTML in email, as well as images loaded from anywhere, but not JavaScript or other potentially dangerous content.

```python
csp = {
    'default-src': [
        '\'self\'',
        '*.mailsite.com',
    ],
    'img-src': '*'
}
```

Note that this example doesn't specify a `script-src`; with the example CSP, this site uses the setting specified by the `default-src` directive, which means that scripts can be loaded only from the originating server.
