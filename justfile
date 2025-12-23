build:
    CGO_ENABLED=0 go build  -o talos-kms-seals ./cmd/talos-kms-seals

push-image tag: build
    docker build . --push -t ghcr.io/michaelbeaumont/talos-kms-seals:{{ tag }}
