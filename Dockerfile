FROM golang:1.13.2-alpine as builder
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

ENV GOCACHE /gocache
ENV CGO_ENABLED 0

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go install
RUN go test -i ./...

FROM scratch
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /app
COPY --from=builder /go/bin/sish /app/sish

ENTRYPOINT ["/app/sish"]
