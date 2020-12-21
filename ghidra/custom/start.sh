GHIDRA_REPOSITORIES_PATH=/repos
if [ ! -e "${GHIDRA_REPOSITORIES_PATH}/users" ]; then
  mkdir -p "${GHIDRA_REPOSITORIES_PATH}/~admin"
  echo "Creating user 'ghidra' with default password 'changeme'"
  echo "-add ghidra" >> "${GHIDRA_REPOSITORIES_PATH}/~admin/adm.cmd"
fi

server/ghidraSvr console
