all: proxy/proxy server/server

proxy/proxy: proto/flag.pb.go proxy/main.go
	CGO_ENABLED=0 go build -o ./proxy/proxy bpftracer/proxy

server/server: proto/flag.pb.go server/main.go
	CGO_ENABLED=0 go build -o ./server/server bpftracer/server

proto/flag.pb.go: proto/flag.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/flag.proto
