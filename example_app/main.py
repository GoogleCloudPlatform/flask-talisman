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
from flask import Flask, request, render_template
from flask.ext.seasurf import SeaSurf
from talisman import Talisman


app = Flask(__name__)
app.secret_key = '123abc'
csrf = SeaSurf(app)
talisman = Talisman(app)


@app.route('/', methods=['GET', 'POST'])
def index():
    message = request.form.get('message', None)
    return render_template('index.html', message=message)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
