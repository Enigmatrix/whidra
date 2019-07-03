FROM openjdk:11-slim
ARG GHIDRA_VERSION=9.0_PUBLIC_20190228
ARG GHIDRA_SHA256=3b65d29024b9decdbb1148b12fe87bcb7f3a6a56ff38475f5dc9dd1cfc7fd6b2
ARG HOST=daniellimws.hopto.org

RUN useradd -m ghidra && \
    mkdir -p /srv/repositories && \
    chown -R ghidra: /srv/repositories && \
    update-alternatives --install "/usr/bin/java" "java" "/usr/local/openjdk-11/bin/java" 0 && \
    update-alternatives --install "/usr/bin/javac" "javac" "/usr/local/openjdk-11/bin/javac" 0

WORKDIR /opt
RUN apt-get update && apt-get install -y unzip wget gettext-base patch sudo ed libfreetype6 libfontconfig1 fontconfig-config libexpat1 fonts-dejavu-core libpng16-16 && \
    wget -q -O ghidra.zip https://ghidra-sre.org/ghidra_${GHIDRA_VERSION}.zip && \
    echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip ghidra.zip && \
    rm ghidra.zip && \
    ln -s ghidra* ghidra && \
    cd ghidra && \
    rm -rf docs && \
    cd .. && \
    chown -R ghidra: ghidra*

VOLUME /srv/repositories
WORKDIR /opt/ghidra
ENV ghidra_home=/opt/ghidra
COPY ./scripts /opt/ghidra/custom_scripts
COPY server.conf /opt/ghidra/server
COPY start.sh /opt/ghidra/server
RUN server/svrInstall

RUN echo "0.0.0.0  ${HOST}" >> /etc/hosts && \
    echo "wrapper.java.additional.4=-Djava.rmi.server.hostname=${HOST}" >> server/server.conf && \
    cp /etc/hosts /opt/ghidra/server

CMD server/start.sh

EXPOSE 13100
EXPOSE 13101
EXPOSE 13102
