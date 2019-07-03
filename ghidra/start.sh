#!/bin/bash

cp server/hosts /etc/hosts

server/svrAdmin -add enigmatrix
server/svrAdmin -add daniellimws
server/svrAdmin -add ghidra
server/ghidraSvr console
