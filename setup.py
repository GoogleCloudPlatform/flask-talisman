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

from codecs import open

from setuptools import setup


long_description = open('README.rst', 'r', encoding='utf-8').read()


setup(
    name='flask-talisman',

    version='0.6.0',

    description='HTTP security headers for Flask.',
    long_description=long_description,

    url='https://github.com/GoogleCloudPlatform/flask-talisman',

    author='Thea Flowers',
    author_email='theaflowers@google.com',

    license='Apache Software License',

    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: Apache Software License',

        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',

        'Operating System :: POSIX',
        'Operating System :: MacOS',
        'Operating System :: Unix',
    ],
    keywords='flask security https xss',

    packages=['flask_talisman'],

    install_requires=['six>=1.9.0'],
)
