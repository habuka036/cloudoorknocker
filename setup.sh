#!/bin/bash -ex

virtualenv .venv --no-site-packages
. .venv/bin/activate
pip install -r requirements.txt
