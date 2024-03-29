cp ./server/src/app.py ../attachments/server.py
cp ./server/src/app_pb2.py ../attachments/app_pb2.py
cp ./server/proto/app.proto ../attachments/app.proto
cp ./waf/src/app.py ../attachments/waf.py
cp ./waf/src/protoless.py ../attachments/protoless.py

cd ../attachments
rm -rf ./challenge.zip
zip -r ./challenge.zip ./*
rm -rf ./server.py ./app_pb2.py ./app.proto ./waf.py ./protoless.py