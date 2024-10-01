# Backfired

v8 commit: 171e9a61e56a06c99d9f65df40f59f340827b6e6. You can use
`Dockerfile.v8build` to build your own binary if you wish (thank me later):

```sh
DOCKER_BUILDKIT=1 docker build -f Dockerfile.v8build --target release --output type=local,dest=build .

# Needed if you run docker as root
sudo chown -R $USER:$USER build
```

GLHF!
