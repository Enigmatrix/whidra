import {Router, Response, Request} from 'express';
import Dockerode from 'simple-dockerode';
import filenamify from 'filenamify';

export const projects = Router();

const docker = new Dockerode();

const ghidraCmd = async (cmd: string[]) => {
    const exec = await docker.getContainer('ghidra_svr').exec(cmd, { stderr: true, stdout: true });
    return exec.stdout;
};

projects.get('/all', async (req: Request, res: Response) => {
    const output = await ghidraCmd(['./server/svrAdmin', '-list']);
    let repos = output.split('queued.\n\nRepositories:\n')[1].split('\n');
    if(repos[0] === '   <No repositories have been created>'){
        repos = [];
    }
    res.json(repos);
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
})
