FROM golang:1.11.5-stretch
LABEL maintainer="Antonio Mika <me@antoniomika.me>"

WORKDIR /usr/local/go/src/github.com/antoniomika/sish

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go install

CMD ["sish"]