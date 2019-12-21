# Base Image {{{

FROM openjdk:11-slim as base
ARG GHIDRA_VERSION=9.1_PUBLIC_20191023
ARG GHIDRA_SHA256=29d130dfe85da6ec45dfbf68a344506a8fdcc7cfe7f64a3e7ffb210052d1875e

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
WORKDIR /opt/ghidra
COPY --chown=ghidra:ghidra ./ghidra/custom/BuildSingleGhidraJar.java /opt/ghidra/custom/BuildSingleGhidraJar.java
RUN ./support/analyzeHeadless . empty -postScript ./custom/BuildSingleGhidraJar.java /opt/ghidra/ghidra.jar -noanalysis -deleteProject && chown ghidra ghidra.jar

VOLUME /srv/repositories
ENV ghidra_home=/opt/ghidra
COPY --chown=ghidra:ghidra ./ghidra/ /opt/ghidra/

RUN server/svrInstall

EXPOSE 13100 13101 13102
USER ghidra

CMD custom/start.sh

# }}}

# Development Image: Backend {{{
FROM base as backend
# }}}

# Development Image: Frontend {{{
# }}}

# Production Image {{{
# }}}
