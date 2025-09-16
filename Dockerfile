FROM golang:latest AS builder
COPY . /srv/crproxy
COPY .git /srv/crproxy/.git
# ENV GOPROXY="https://goproxy.cn,direct"
RUN cd /srv/crproxy && make build && ls -l bin

# download ca-certificates
FROM alpine:latest AS ca
# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk --no-cache add ca-certificates

# get the final image
FROM scratch
LABEL source.url="https://github.com/fimreal/crproxy"

COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /srv/crproxy/bin/crproxy /crproxy

ENTRYPOINT [ "/crproxy" ]