# whidra

Stands for **W**eb G**hidra**


## Development
There is hot reloading for the frontend when you run `./dev/sh`.
If you want to use IntelliJ IDEA with all its type completion glory, you will need to build `ghidra.jar`
``` bash
analyzeHeadless empty . -postScript path/to/project/ghidra/server/BuildSingleGhidraJar.java path/to/project/ghidra/ghidra.jar -deleteProject -noanalysis
```
