FROM gcr.io/kctf-docker/challenge@sha256:d884e54146b71baf91603d5b73e563eaffc5a42d494b1e32341a5f76363060fb

RUN apt update && \
    apt install -y curl && \
    curl -sL https://deb.nodesource.com/setup_18.x | bash - && \
    apt install -y nodejs git mysql-client \
    && rm -rf /var/lib/apt/lists/*

COPY src/ /home/app/
COPY bot.js /home/app/

RUN cd /home/app/js/static && \
    git clone --depth 1 https://github.com/shhnjk/closure-library.git && \
    cd closure-library && \
    npm install

WORKDIR /home/app/

VOLUME /tmp/db

RUN npm ci --only=production
ENV NODE_ENV "production"

COPY ./start.sh /tmp

CMD kctf_setup && \
    /tmp/start.sh

