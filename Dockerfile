FROM golang:latest AS builder
ARG VERSION=unknown
COPY . /srv/crproxy
# ENV GOPROXY="https://goproxy.cn,direct"
RUN cd /srv/crproxy && make build VERSION=${VERSION} && ls -l bin

# download ca-certificates
FROM alpine:latest AS ca
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk --no-cache add ca-certificates

# get the final image
FROM scratch

COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /srv/crproxy/bin/crproxy /crproxy

ENTRYPOINT [ "/crproxy" ]