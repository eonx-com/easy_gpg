#!/usr/bin/env bash

cd "$(dirname "$0")"

echo Installing serverless dependencies...
npm install serverless-python-requirements --save-dev
npm install serverless-deployment-bucket --save-dev

echo Configuring Python virtual environment...
rm -rf ./venv
python3 -m venv ./venv
source ./venv/bin/activate
pip3 install --upgrade pip

echo Installing Python project dependencies...
pip3 install -r ./requirements.txt

