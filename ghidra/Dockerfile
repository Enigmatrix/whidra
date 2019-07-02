FROM bskaggs/ghidra
RUN mkdir /opt/ghidra/custom_scripts
USER root
RUN apt install -y libfreetype6 libfontconfig1 fontconfig-config libexpat1 fonts-dejavu-core libpng16-16
USER ghidra
COPY ./scripts /opt/ghidra/custom_scripts
CMD bash -c "mkdir -p '/srv/repositories/~admin' && \
    echo '-add enigmatrix' > '/srv/repositories/~admin/adm.cmd' && \
    echo '-add daniellimws' > '/srv/repositories/~admin/adm.cmd' && \
    echo '-add ghidra' >> '/srv/repositories/~admin/adm.cmd' && \
    /opt/ghidra/server.sh"
