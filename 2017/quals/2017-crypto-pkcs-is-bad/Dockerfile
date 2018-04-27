FROM golang:latest
ADD . /go
WORKDIR /go
RUN go build -o 2017-crypto-pkcs-is-bad
CMD ["/go/2017-crypto-pkcs-is-bad"]
EXPOSE 8080
