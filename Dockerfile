FROM golang:1.11.5-alpine3.9 as downloader
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

RUN apk add --no-cache git gcc musl-dev

WORKDIR /usr/local/go/src/github.com/antoniomika/sish

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM golang:1.11.5-alpine3.9 as builder
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

RUN apk add --no-cache git gcc musl-dev

COPY --from=downloader /go/ /go/
COPY --from=downloader /usr/local/go/ /usr/local/go/

WORKDIR /usr/local/go/src/github.com/antoniomika/sish

COPY . .

RUN go install

FROM alpine as runner
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

COPY --from=builder /usr/local/go/src/github.com/antoniomika/sish /sish
COPY --from=builder /go/bin/sish /sish/sish

WORKDIR /sish

ENTRYPOINT ["/sish/sish"]
