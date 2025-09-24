build:
    CGO_ENABLED=0 go build  -o talos-kms-seals ./cmd/talos-kms-seals

push-image: build
    docker build . --push -t ghcr.io/michaelbeaumont/talos-kms-seals:latest
