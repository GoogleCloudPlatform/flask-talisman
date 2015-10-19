FROM google/python-runtime

ENTRYPOINT /env/bin/gunicorn -c gunicorn.conf.py -b 0.0.0.0:8080 main:app
