# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

all: vm/initramfs.cpio server/server

vm/initramfs.cpio: proxy/proxy vm/initramfs/init
	cp proxy/proxy vm/initramfs/proxy
	(cd vm/initramfs && find . | cpio --format newc -o) >vm/initramfs.cpio

proxy/proxy: proto/flag.pb.go proxy/main.go
	CGO_ENABLED=0 go build -o ./proxy/proxy bpftracer/proxy

server/server: proto/flag.pb.go server/main.go
	CGO_ENABLED=0 go build -o ./server/server bpftracer/server

proto/flag.pb.go: proto/flag.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/flag.proto
