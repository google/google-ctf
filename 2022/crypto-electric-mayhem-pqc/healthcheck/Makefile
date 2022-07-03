all: pqcrypto/kyber.cpython-38-x86_64-linux-gnu.so

# Use tar to dereference the symlinks to third_party.
# https://stackoverflow.com/questions/31881904/docker-follow-symlink-outside-context
pqcrypto/kyber.cpython-38-x86_64-linux-gnu.so: pqcrypto/builder.py pqcrypto.dockerfile
	- docker rm tmp-pqcrypto-container 2>/dev/null
	tar -czh . | docker build -t tmp-pqcrypto-image -f pqcrypto.dockerfile -
	docker run --name tmp-pqcrypto-container tmp-pqcrypto-image /bin/true
	docker cp tmp-pqcrypto-container:/build/pqcrypto/pqcrypto/kyber.cpython-38-x86_64-linux-gnu.so pqcrypto
	- docker rm tmp-pqcrypto-container 2>/dev/null
	touch pqcrypto/kyber.cpython-38-x86_64-linux-gnu.so

clean:
	rm pqcrypto/kyber.cpython-38-x86_64-linux-gnu.so
