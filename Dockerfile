FROM golang:1.14-alpine as builder
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

ENV GOCACHE /gocache
ENV CGO_ENABLED 0

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN go install -ldflags="-s -w -X cmd.Version=${VERSION} -X cmd.Commit=${COMMIT} -X cmd.Date=${DATE}"
RUN go test -i ./...

FROM scratch
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /app

COPY --from=builder /tmp /tmp
COPY --from=builder /app/pubkeys /app/pubkeys
COPY --from=builder /app/templates /app/templates
COPY --from=builder /go/bin/sish /app/sish

ENTRYPOINT ["/app/sish"]
