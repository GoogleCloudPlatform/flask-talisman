# Copyright 2015 Google Inc. All Rights Reserved.
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

from flask import Flask, render_template, request
from flask_seasurf import SeaSurf
from flask_talisman import Talisman


app = Flask(__name__)
app.secret_key = '123abc'
csrf = SeaSurf(app)

SELF = "'self'"
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': SELF,
        'img-src': '*',
        'script-src': [
            SELF,
            'some.cdn.com',
        ],
        'style-src': [
            SELF,
            'another.cdn.com',
        ],
    },
    content_security_policy_nonce_in=['script-src'],
    feature_policy={
        'geolocation': '\'none\'',
    },
    permissions_policy={
        'geolocation': '()',
    }
)


@app.route('/', methods=['GET', 'POST'])
def index():
    message = request.form.get('message', None)
    return render_template('index.html', message=message)


# Example of a route-specific talisman configuration
@app.route('/embeddable')
@talisman(
    frame_options='ALLOW-FROM',
    frame_options_allow_from='https://example.com/',
)
def embeddable():
    return "<html>I can be embedded.</html>"


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
