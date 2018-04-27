FROM python:2.7

RUN set -e -x ;\
        groupadd -g 1337 user ;\
        useradd -m -u 1337 -g 1337 user

ADD repository/challenge/challenge.py challenge.py
ADD repository/challenge/flag.txt flag.txt

RUN set -e -x ;\
        chown user:user challenge.py flag.txt ;\
        chmod 400 challenge.py flag.txt

CMD python challenge.py
