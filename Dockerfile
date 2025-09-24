FROM debian:12 AS debian

RUN cd /tmp
# All packages in the dependency tree of cryptsetup
RUN apt-get update \
    && apt-get download \
      libblkid1 libcryptsetup12 libpopt0 libuuid1 libargon2-1 libdevmapper1.02.1 libjson-c5 libselinux1 libudev1 libpcre2-8-0 \
      cryptsetup-bin \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN for deb in *.deb; do dpkg --extract $deb /tmp/cryptsetup; done

FROM gcr.io/distroless/cc-debian12
LABEL org.opencontainers.image.source="https://github.com/michaelbeaumont/talos-kms-seals"

COPY --from=debian /tmp/cryptsetup /

COPY ./talos-kms-seals /usr/local/bin/talos-kms-seals
ENTRYPOINT ["/usr/local/bin/talos-kms-seals"]
