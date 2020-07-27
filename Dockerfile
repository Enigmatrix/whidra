# Base Images {{{
FROM openjdk:11-slim as jvm
RUN update-alternatives --install "/usr/bin/java" "java" "/usr/local/openjdk-11/bin/java" 0 && \
    update-alternatives --install "/usr/bin/javac" "javac" "/usr/local/openjdk-11/bin/javac" 0
RUN apt-get update && apt-get install -y unzip wget gettext-base patch sudo ed libfreetype6 libfontconfig1 fontconfig-config libexpat1 fonts-dejavu-core libpng16-16 entr

FROM jvm as ghidra
ARG GHIDRA_VERSION=9.0_PUBLIC_20190228
ARG GHIDRA_SHA256=3b65d29024b9decdbb1148b12fe87bcb7f3a6a56ff38475f5dc9dd1cfc7fd6b2

RUN useradd -m ghidra && \
    mkdir -p /repos && \
    chown -R ghidra: /repos

WORKDIR /opt
RUN wget -q -O ghidra.zip https://ghidra-sre.org/ghidra_${GHIDRA_VERSION}.zip && \
    echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip ghidra.zip && \
    rm ghidra.zip && \
    ln -s ghidra* ghidra && \
    cd ghidra && \
    rm -rf docs && \
    cd .. && chown -R ghidra: ghidra*
WORKDIR /opt/ghidra

COPY --chown=ghidra:ghidra
    ./ghidra/custom/BuildSingleGhidraJar.java
    /opt/ghidra/custom/BuildSingleGhidraJar.java
RUN ./support/analyzeHeadless . empty -postScript
    ./custom/BuildSingleGhidraJar.java /opt/ghidra/ghidra.jar
    -noanalysis -deleteProject
    && chown ghidra ghidra.jar

VOLUME /repos
ENV ghidra_home=/opt/ghidra
COPY --chown=ghidra:ghidra ./ghidra/ /opt/ghidra/

RUN server/svrInstall

EXPOSE 13100 13101 13102
USER ghidra

CMD custom/start.sh
# }}}

FROM ghidra AS ghidra-dev
FROM ghidra AS ghidra-prod
