#!/bin/bash

server/ghidraSvr start
server/ghidraSvr stop
server/svrAdmin -add ghidra
{ (cd bridge && ./gradlew --no-daemon run) & server/ghidraSvr console -u; }
