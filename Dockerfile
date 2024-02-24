FROM debian:bookworm as builder

RUN apt update && \
    apt install -y haxe sudo git curl wget gnupg2
RUN curl -sL https://deb.nodesource.com/setup_21.x | sudo -E bash -
RUN apt install -y nodejs

#RUN git clone https://github.com/jonasmalacofilho/git-cache-http-server.git /tmp/git-cache-http-server
WORKDIR /tmp/git-cache-http-server
COPY ./build.hxml /tmp/git-cache-http-server
RUN haxelib setup /usr/share/haxelib/
RUN haxelib install hxnodejs
RUN haxelib install random
RUN haxelib install PBKDF2
RUN haxelib git jmf-npm-externs https://github.com/jonasmalacofilho/jmf-npm-externs.hx.git master
COPY ./ /tmp/git-cache-http-server
RUN haxe build.hxml
RUN npm pack 

FROM node:alpine

RUN apk add --no-cache git tini
COPY --from=builder /tmp/git-cache-http-server/*tgz /tmp/
RUN npm install -g /tmp/*tgz
COPY CS-US1-SF-CA.pem /usr/local/share/ca-certificates/CS-US1-SF-CA.crt
ENV NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/CS-US1-SF-CA.crt" \
    CUSTOM_CA_PATH="/usr/local/share/ca-certificates/CS-US1-SF-CA.crt"
RUN git config --system http.sslcainfo /usr/local/share/ca-certificates/CS-US1-SF-CA.crt

EXPOSE 8080

VOLUME ["/tmp/cache/git"]

STOPSIGNAL SIGTERM

ENTRYPOINT ["/sbin/tini", "--"]

CMD ["git-cache-http-server", "--port", "8080", "--cache-dir", "/tmp/cache/git"]
