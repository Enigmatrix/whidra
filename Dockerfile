# --- Base Java Image ---
FROM openjdk:11-slim as jvm
RUN update-alternatives --install "/usr/bin/java" "java" "/usr/local/openjdk-11/bin/java" 0 && \
    update-alternatives --install "/usr/bin/javac" "javac" "/usr/local/openjdk-11/bin/javac" 0
RUN apt-get update && apt-get install -y unzip wget gettext-base patch sudo ed libfreetype6 libfontconfig1 fontconfig-config libexpat1 fonts-dejavu-core libpng16-16
# -----------------------

# --- Base Ghidra Image ---
FROM jvm as ghidra
ARG GHIDRA_VERSION=9.2_PUBLIC_20201113
ARG GHIDRA_SHA256=ffebd3d87bc7c6d9ae1766dd3293d1fdab3232a99b170f8ea8b57497a1704ff6

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

COPY --chown=ghidra:ghidra ./ghidra/custom/ /opt/ghidra/custom/
RUN ./custom/buildSingleJar.sh && chown ghidra ghidra.jar

VOLUME /repos
ENV ghidra_home=/opt/ghidra
COPY --chown=ghidra:ghidra ./ghidra/ /opt/ghidra/

RUN server/svrInstall

EXPOSE 13100 13101 13102
USER ghidra

CMD custom/start.sh
# ------------------------

FROM ghidra AS ghidra-dev
FROM ghidra AS ghidra-prod
