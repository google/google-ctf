FROM debian


# Install deps
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y supervisor curl apache2 apache2-utils imagemagick-6.q16 libapache2-mod-php7.0 php-dom \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

RUN set -e -x; groupadd -g 1337 user; useradd -g 1337 -u 1337 -m user
RUN set -e -x; groupadd -g 1338 admin; useradd -g 1338 -u 1338 -m admin

RUN rm /etc/php/*/apache2/conf.d/*phar.ini
ADD deploy/app/ /var/www/html/
RUN rm /var/www/html/index.html
RUN mkdir /var/www/html/upload && chmod 777 /var/www/html/upload
RUN touch /var/www/html/upload/index.html

ADD deploy/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
ADD deploy/hosts /etc
ADD deploy/apache2.conf /etc/apache2
ADD deploy/supervisor_listener.py /usr/bin/
RUN chmod 755 /usr/bin/supervisor_listener.py
RUN sed -i 's/Listen 80/Listen 1337/' /etc/apache2/ports.conf && chmod -R 644 /var/www/html/*php /etc/supervisor/conf.d/* /etc/apache2/apache2.conf

ADD deploy/get_flag /
RUN chown admin:admin /get_flag && chmod 4755 /get_flag
RUN echo -n 'CTF{8d62b2ffc578227e67ca8bab53420ded}' > /flag && chmod 600 /flag && chown admin:admin /flag

# Not used, only for documentation purposes.
EXPOSE 1337

ADD deploy/run.sh /run.sh

ENTRYPOINT /run.sh

