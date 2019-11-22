FROM debian
RUN apt-get update -y
RUN apt-get install -y python3-pip python3-dev build-essential imagemagick libmagickwand-dev supervisor

RUN set -e -x; groupadd -g 1337 user; useradd -g 1337 -u 1337 -m user
RUN set -e -x; groupadd -g 1338 admin; useradd -g 1338 -u 1338 -m admin

ADD get_flag /
RUN chown admin:admin /get_flag && chmod 4755 /get_flag
RUN echo -n 'CTF{xO_Ox}' > /flag && chmod 600 /flag && chown admin:admin /flag

COPY app/ /app
WORKDIR /app
RUN chown user:user -R /app
RUN chmod 777 media

RUN pip3 install -r requirements.txt
EXPOSE 8080

ADD deploy/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ADD deploy/supervisor_listener.py /usr/bin/
RUN chmod 755 /usr/bin/supervisor_listener.py
RUN chmod a+r /etc/supervisor/conf.d/supervisord.conf

CMD ["gunicorn", "-b", "0.0.0.0:8080", "main:app"]
