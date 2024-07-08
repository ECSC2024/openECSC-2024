#!/bin/bash

# clean workdir
rm -rf ../attachments/*

# copy source
cp -r backend ../attachments/backend
cp -r frontend ../attachments/frontend
cp -r proxy ../attachments/proxy
cp -r docker-compose.yml ../attachments/docker-compose.yml
cp -r Dockerfile ../attachments/Dockerfile
cp -r requirements.txt ../attachments/requirements.txt

cd ../attachments

# censor flag generation
rm backend/secret.py
sed -i "s/get_flag()/os.getenv('FLAG', 'TeamItaly{REDACTED}')/" backend/app.py
sed -i "/from secret import get_flag/d" backend/app.py

sed -i "s/FLAG: .*$/FLAG: TeamItaly{REDACTED}/" docker-compose.yml
sed -i "s/MONGO_INITDB_ROOT_PASSWORD: .*$/MONGO_INITDB_ROOT_PASSWORD: password/" docker-compose.yml
sed -i "s/HEADLESS_AUTH: .*$/HEADLESS_AUTH: supersecret/" docker-compose.yml
sed -i "s/POW_BYPASS: .*$/POW_BYPASS: redacted/" docker-compose.yml
sed -i "s/AUTH_TOKEN: .*$/AUTH_TOKEN: supersecret/" docker-compose.yml
sed -i "s/MONGO_PASSWORD: .*$/MONGO_PASSWORD: password/" docker-compose.yml

# create zip
zip smaug.zip -r backend frontend proxy docker-compose.yml Dockerfile requirements.txt

# clean workdir
rm -rf backend frontend proxy docker-compose.yml Dockerfile requirements.txt