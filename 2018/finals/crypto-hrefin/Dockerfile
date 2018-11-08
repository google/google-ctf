FROM debian

RUN set -e -x; \
  groupadd -g 1337 www; \
  useradd -g 1337 -u 1337 -m www
# Install deps
RUN apt-get update
RUN apt-get install -y curl python python-dev build-essential gcc supervisor
RUN rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
RUN python get-pip.py

ADD chall/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chmod +r /etc/supervisor/conf.d/supervisord.conf

ADD chall /chall
RUN chown -R root:root /chall
RUN chown www:www /chall
RUN chmod -R 0755 /chall

RUN pip install -r /chall/requirements.txt

USER www
WORKDIR /chall

EXPOSE 8080 8081

ENV HTTP_PORT 8080
ENV HTTPS_PORT 8081
# ssl domain
ENV DOMAIN localhost
ENV GOOGLE_APPLICATION_CREDENTIALS /chall/creds.json

CMD ./run.sh

