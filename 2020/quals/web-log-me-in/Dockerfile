FROM mysql/mysql-server:latest

ENV MYSQL_ROOT_PASSWORD "kajsdfouyhsdfhl"

COPY sql/dbsetup.sh /docker-entrypoint-initdb.d/
run chmod +x /docker-entrypoint-initdb.d/dbsetup.sh
COPY sql/setup.sql /
