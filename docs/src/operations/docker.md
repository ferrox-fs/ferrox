# Docker

Ferrox ships a multi-stage `Dockerfile` that produces a < 20 MB statically-linked image (musl, `FROM scratch` final stage).

## Run

```sh
docker run --rm -p 9000:9000 -v ferrox-data:/data \
  ghcr.io/ferrox-rs/ferrox:latest \
  --data-dir /data --bind 0.0.0.0:9000
```

## docker-compose

```yaml
services:
  ferrox:
    image: ghcr.io/ferrox-rs/ferrox:latest
    ports:
      - "9000:9000"
    volumes:
      - ferrox-data:/data
    environment:
      FERROX_ACCESS_KEY: minioadmin
      FERROX_SECRET_KEY: minioadmin
volumes:
  ferrox-data: {}
```

## Build locally

```sh
docker build -t ferrox:dev .
```
