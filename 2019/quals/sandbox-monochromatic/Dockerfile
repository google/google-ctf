FROM debian:testing
RUN set -e -x; \
        apt-get -y update; \
        apt-get -y upgrade; \
        apt-get -y dist-upgrade; \
	apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https software-properties-common; \
	apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https python2.7; \
	apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https g++; \
    apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https wget; \
    apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https curl; \
    apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https iputils-ping; \
    apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https libx11-6 libx11-xcb1 libxcb1; \
    apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https libasound2 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 \ 
     libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 \ 
     libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 \ 
     libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \ 
     libnss3 ; \
    apt-get --no-install-recommends -q install -y apt-utils ca-certificates apt-transport-https libpulse0;

RUN set -e -x; \
    groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user

COPY src/binary/ /home/user/binary
COPY flag /home/user/flag
COPY src/service.py /home/user/service.py

RUN set -e -x ;\
      chown -R user:user /home/user

USER user
CMD chmod +x /home/user/binary/chrome && cd /home/user/ && python2.7 service.py
