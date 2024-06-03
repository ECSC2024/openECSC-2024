docker compose up --build --force-recreate -d
docker cp nftp_compiler:/home/rust/src/target/x86_64-unknown-linux-musl/release/nftp ./nftp
cp ./nftp ../../attachments/nftp
rm ./nftp