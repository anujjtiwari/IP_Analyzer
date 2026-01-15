#!/bin/bash
pip3 install pipenv
pipenv install django
pipenv run pip install -r requirements.txt
mongosh ip_analyzer -f setup.js