FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

RUN apt update && \
    apt install -y curl unzip sqlite3 mysql-client && \
    curl -fsSL https://deno.land/x/install/install.sh | sh \
    && rm -rf /var/lib/apt/lists/*

COPY src/ /home/app/

WORKDIR /home/app

VOLUME /tmp/db

ENV PATH "/root/.deno/bin:$PATH"

VOLUME /root/.cache
RUN deno cache main.ts

COPY ./start.sh /tmp

CMD kctf_setup && \
    /tmp/start.sh

