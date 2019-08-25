#!/bin/bash

server/ghidraSvr start
server/ghidraSvr stop
server/svrAdmin -add enigmatrix
server/svrAdmin -add daniellimws
server/svrAdmin -add ubuntu-dev
server/svrAdmin -add cexplr
server/svrAdmin -add ghidra
{ (cd bridge; ./gradlew run) & server/ghidraSvr console; }

#{ server/ghidraSvr -u console; }
