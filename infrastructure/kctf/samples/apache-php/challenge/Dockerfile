FROM kctf-nsjail

RUN apt-get -y update
RUN apt-get -y upgrade

RUN ln -s /secrets/flag /chroot/flag

VOLUME /tmp
VOLUME /var/log/apache2
VOLUME /var/run/apache2

RUN apt-get install -y php-cgi
RUN apt-get install -y apache2

RUN service apache2 start

COPY html/ /chroot/var/www/html/
RUN chmod -R 0755 /chroot/var/www/html
RUN rm -rf /var/www
RUN ln -s /chroot/var/www /var/www

RUN mkdir -p /chroot/usr/lib/cgi-bin/
RUN cp /usr/lib/cgi-bin/php /chroot/usr/lib/cgi-bin/php
RUN ldd /usr/lib/cgi-bin/php | cut -d' ' -f 3 | xargs -r -i cp {} /chroot{}

RUN ln -s /etc/apache2/mods-available/cgi.load /etc/apache2/mods-enabled/cgi.load
RUN ln -s /etc/apache2/mods-available/actions.load /etc/apache2/mods-enabled/actions.load

RUN ln -s /config/apache2-nsjail-php.conf /etc/apache2/conf-enabled/nsjail-php.conf

COPY files/nsjail-php-cgi /usr/lib/cgi-bin/nsjail-php-cgi
RUN chmod 0755 /usr/lib/cgi-bin/nsjail-php-cgi

COPY files/nsjail-apache /root/nsjail-apache
RUN chmod 0755 /root/nsjail-apache

CMD /root/nsjail-apache
