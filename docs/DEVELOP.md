# Setup
## Pre-requisites

### Server
- IntelliJ IDEA or any other decent Kotlin editor (needs annotation support)
- Gradle
- Docker that can run Linux containers 
- Installation of Ghidra that matches the latest stable release

### Client
- NodeJS

## Recommendation
- The `ghidra-dev` docker image should be running in the background as the Ghidra Server.
- A single ghidra jar should be built via running
```sh
./ghidra/custom/buildSingleJar.sh /path/to/local/ghidra .
```
- Check that a ghidra.jar exists in the root directory of the project.
- The `server` should be open in IntelliJ IDEA, with [Kotlin annotations support](https://immutables.github.io/apt.html#:~:text=To%20configure%20annotation%20processing%20in,classpath%20and%20specify%20output%20directories.&text=After%20you%20do%20this%2C%20classes,generated%20on%20each%20project%20build.).
- The `client` should be run via `npm run serve`, and edited via any editor of your choice.