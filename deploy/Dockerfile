FROM debian:bookworm-slim

ENV XDG_DATA_HOME=/data

COPY server /usr/local/bin/server

EXPOSE 4433/udp

ENTRYPOINT ["/usr/local/bin/server"]
