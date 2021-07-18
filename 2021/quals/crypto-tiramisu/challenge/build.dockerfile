FROM golang:latest as build

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN go build -o challenge cmd/server.go

CMD sleep 1
