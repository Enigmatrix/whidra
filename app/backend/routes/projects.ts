import {Router, Response, Request} from 'express';
import filenamify from 'filenamify';
import {ghidraCmd, parseList} from '../ghidra';

export const projects = Router();

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

    const cmd = ['./support/analyzeHeadless', '.', 'empty',
        '-postScript', '/opt/ghidra/custom_scripts/CreateProject.java', name, '-deleteProject', '-noanalysis'];

    const output = await ghidraCmd(cmd);
    res.json(output);
})

projects.get('/:project/binaries', async (req: Request, res: Response) => {
    const {project} = req.params;
    const cmd = ['./support/analyzeHeadless', 'ghidra://localhost/'+project,
        '-postScript', '/opt/ghidra/custom_scripts/GetProjectBinaries.java', '-noanalysis', '-p'];
    const output = parseList(await ghidraCmd(cmd, true));
    res.json(output);
})
