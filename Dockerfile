FROM golang:1.14-alpine as builder
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

ENV GOCACHE /gocache
ENV CGO_ENABLED 0

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN go install -ldflags="-s -w -X github.com/antoniomika/sish/cmd.Version=${VERSION} -X github.com/antoniomika/sish/cmd.Commit=${COMMIT} -X github.com/antoniomika/sish/cmd.Date=${DATE}"
RUN go test -i ./...

FROM scratch
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /app

COPY --from=builder /tmp /tmp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/deploy/pubkeys /app/deploy/pubkeys
COPY --from=builder /app/templates /app/templates
COPY --from=builder /go/bin/sish /app/sish

ENTRYPOINT ["/app/sish"]
