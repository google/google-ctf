FROM debian:testing
RUN set -e -x; \
    apt-get -y update; \
    apt-get -y upgrade; \
    apt-get -y dist-upgrade; \
    apt-get install -y software-properties-common; \
    apt-get install -y python2.7; \
    apt-get install -y g++; \
    apt-get install -y wget; \
    apt-get install -y curl; \
    apt-get install -y iputils-ping; \
    apt-get install -y libx11-6 libx11-xcb1 libxcb1; \
    apt-get install -y libasound2 libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 \ 
     libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 \ 
     libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 \ 
     libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \ 
     libnss3; \
    apt-get install -y libpulse0; \
    apt-get install -y libgbm1; \
    apt-get install -y xvfb;

RUN set -e -x; \
    groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user

COPY attachments/chrome /home/user/chrome
COPY attachments/service.py /home/user/
COPY flag /home/user/flag

RUN set -e -x; \
    chown -R root:root /home/user; \
    chmod -R a+r /home/user/chrome; \
    chmod +x /home/user/chrome/locales; \
    chmod +x /home/user/chrome/MEIPreload; \
    chmod +x /home/user/chrome/swiftshader; \
    chmod 555 /home/user/chrome/chrome; \
    chmod 555 /home/user/service.py; \
    chmod 444 /home/user/flag

CMD mkdir -m 01777 /tmp/.X11-unix && cd /home/user/ && su user -c 'sh -c "Xvfb :100 & ./service.py"'
