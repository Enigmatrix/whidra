# build frontend
FROM node:11.3-slim as frontend-builder
COPY ./webapp/package.json /app/
COPY ./webapp/yarn.lock /app/
WORKDIR /app
RUN yarn install
COPY ./webapp /app/
RUN yarn build

# main docker images
FROM openjdk:11-slim
ARG GHIDRA_VERSION=9.0_PUBLIC_20190228
ARG GHIDRA_SHA256=3b65d29024b9decdbb1148b12fe87bcb7f3a6a56ff38475f5dc9dd1cfc7fd6b2

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
    cd .. && chown -R ghidra: ghidra* 

VOLUME /srv/repositories

WORKDIR /opt/ghidra
ENV ghidra_home=/opt/ghidra

COPY --chown=ghidra:ghidra ./ghidra/server /opt/ghidra/server
RUN ./support/analyzeHeadless . empty -postScript ./server/BuildSingleGhidraJar.java /opt/ghidra/ghidra.jar -noanalysis -deleteProject && chown ghidra ghidra.jar

RUN server/svrInstall

EXPOSE 13100 13101 13102
RUN mkdir /var/sessions && chown ghidra /var/sessions
USER ghidra
# inherit perms
VOLUME /var/sessions

COPY --chown=ghidra:ghidra ./ghidra/bridge /opt/ghidra/bridge
COPY --chown=ghidra:ghidra --from=frontend-builder /app/dist /opt/ghidra/bridge/frontend

CMD server/start.sh
