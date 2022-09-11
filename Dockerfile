FROM --platform=$BUILDPLATFORM golang:1.19-alpine as builder
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

ENV CGO_ENABLED 0

WORKDIR /app

RUN mkdir -p /emptydir
RUN apk add --no-cache git ca-certificates

COPY go.* ./

RUN go mod download

FROM builder as build-image

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
ARG REPOSITORY=unknown

ARG TARGETOS
ARG TARGETARCH

ENV GOOS=${TARGETOS} GOARCH=${TARGETARCH}

RUN go build -o /go/bin/app -ldflags="-s -w -X github.com/${REPOSITORY}/cmd.Version=${VERSION} -X github.com/${REPOSITORY}/cmd.Commit=${COMMIT} -X github.com/${REPOSITORY}/cmd.Date=${DATE}"

ENTRYPOINT ["/go/bin/app"]

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
