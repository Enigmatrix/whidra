FROM bskaggs/ghidra
CMD bash -c "mkdir -p '/srv/repositories/~admin' && \
    echo '-add enigmatrix' > '/srv/repositories/~admin/adm.cmd' && \
    echo '-add ghidra' >> '/srv/repositories/~admin/adm.cmd' && \
    /opt/ghidra/server.sh"
