challenge: cmd/server.go challenger/challenger.go pb/challenge.proto pb/challenge.pb.go build.dockerfile
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/challenge .
	- docker rm tmp-chal-container 2>/dev/null
	touch challenge
