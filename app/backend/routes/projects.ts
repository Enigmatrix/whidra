import {Router, Response, Request} from 'express';
import Dockerode from 'simple-dockerode';
import filenamify from 'filenamify';

export const projects = Router();

const docker = new Dockerode();

const ghidraCmd = async (cmd: string[], sendPass:boolean=false) => {
    const exec = await docker.getContainer('ghidra_svr').exec(cmd,
        { stderr: true, stdout: true, stdin: sendPass ? 'changeme' : undefined });
    return exec.stdout;
};

const parseList = (str: string): string[] => {
     return str.split("LIST BEGIN")[1]
        .split("LIST END")[0].split('\n')
        .slice(1,-1)
        .map(x => x.split("> ")[1].split(" (GhidraScript)")[0]);
};

projects.get('/all', async (req: Request, res: Response) => {
    const output = await ghidraCmd(['./server/svrAdmin', '-list']);
    let repos = output.split('queued.\n\nRepositories:\n')[1].split('\n');
    if(repos[0] === '   <No repositories have been created>'){
        repos = [];
    }
    res.json(repos.slice(0, -2).map(x => x.trim()));
})

projects.post('/new', async (req: Request, res: Response) => {
    let {name} = req.body;
    name = filenamify(name, {replacement: '_'});

    const cmd = ['./support/analyzeHeadless', '.', 'empty', '-postScript',
        '/opt/ghidra/custom_scripts/CreateProject.java', name, '-deleteProject', '-noanalysis'];

    const output = await ghidraCmd(cmd);
    res.json(output);
})

projects.get('/:project/binaries', async (req: Request, res: Response) => {
    const {project} = req.params;
    const cmd = ['./support/analyzeHeadless', 'ghidra://localhost/'+project, '-postScript', '/opt/ghidra/custom_scripts/GetProjectBinaries.java', '-noanalysis', '-p'];
    const output = parseList(await ghidraCmd(cmd, true));
    res.json(output);
})
