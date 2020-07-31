GHIDRA_PATH=${1:-.}
OUT=${2:-/opt/ghidra}

$GHIDRA_PATH/support/analyzeHeadless . empty -postScript ./custom/BuildSingleGhidraJar.java $OUT/ghidra.jar -noanalysis -deleteProject