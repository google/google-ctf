# Copyright 2021 Google LLC
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

# Please use docker for building your challenges so that SREs can rebuild it
# if necessary without installing any dependencies.

all: bzImage root.cpio.gz attachments-root.cpio.gz

bzImage root.cpio.gz attachments-root.cpio.gz: build.dockerfile bpf_verifier.h.patch verifier.c.patch kernel.config flag gen_cpio.sh initramfs/init
	- docker rm tmp-chal-container 2>/dev/null
	docker build -t tmp-chal-image -f build.dockerfile .
	docker run --name tmp-chal-container tmp-chal-image /bin/true
	docker cp tmp-chal-container:/build/linux/arch/x86/boot/bzImage .
	docker cp tmp-chal-container:/build/root.cpio.gz .
	docker cp tmp-chal-container:/build/attachments-root.cpio.gz .
	- docker rm tmp-chal-container 2>/dev/null
	touch bzImage root.cpio.gz attachments-root.cpio.gz

clean:
	rm -f initramfs/flag
	rm -f root.cpio.gz
	rm -f bzImage
