import Dockerode from 'simple-dockerode';
const docker = new Dockerode();

export const ghidraCmd = async (cmd: string[], sendPass:boolean=false) => {
    const exec = await docker.getContainer('ghidra_svr').exec(cmd,
        { stderr: true, stdout: true, stdin: sendPass ? 'changeme' : undefined });
    return exec.stdout;
};

export const parseList = (str: string): string[] => {
     return str.split("LIST BEGIN")[1]
        .split("LIST END")[0].split('\n')
        .slice(1,-1)
        .map(x => x.split("> ")[1].split(" (GhidraScript)")[0]);
};

