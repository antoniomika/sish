# syntax = docker/dockerfile:experimental
FROM --platform=$BUILDPLATFORM golang:1.15-alpine as builder
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

ENV CGO_ENABLED 0

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG REPOSITORY=unknown

WORKDIR /app

RUN mkdir -p /emptydir
RUN apk add --no-cache git ca-certificates

RUN --mount=type=bind,target=/cache,from=antoniomika/sish-build-cache \
    mkdir -p /go/pkg/ && cp -R /cache/mod/ /go/pkg/ || true && \
    mkdir -p /root/.cache/ && cp -R /cache/go-build/ /root/.cache/ || true

COPY . .

RUN go generate ./...
RUN go test ./...

FROM scratch as build-cache
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

COPY --from=builder /go/pkg/mod /mod
COPY --from=builder /root/.cache/go-build /go-build

FROM builder as build-image

ARG TARGETOS
ARG TARGETARCH

ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}

RUN go build -o /go/bin/app -ldflags="-s -w -X github.com/${REPOSITORY}/cmd.Version=${VERSION} -X github.com/${REPOSITORY}/cmd.Commit=${COMMIT} -X github.com/${REPOSITORY}/cmd.Date=${DATE}"

FROM scratch as release
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /app

COPY --from=build-image /emptydir /tmp
COPY --from=build-image /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-image /app/deploy/ /app/deploy/
COPY --from=build-image /app/README* /app/LICENSE* /app/
COPY --from=build-image /app/templates /app/templates
COPY --from=build-image /go/bin/ /app/

ENTRYPOINT ["/app/app"]
