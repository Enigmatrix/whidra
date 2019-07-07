import {Router, Request, Response} from 'express';
import {ghidraCmd, parseList} from '../ghidra';

export const binary = Router();

binary.get('/:project/:binary/functions', async (req: Request, res: Response) => {
    const {project, binary} = req.params;
    const cmd = ['./support/analyzeHeadless', 'ghidra://localhost/'+project, '-process', binary,
        '-postScript', '/opt/ghidra/custom_scripts/FunctionListing.java', '-readonly', '-p']
    const out = await ghidraCmd(cmd, true);
    const list = parseList(out).map(x => x.split('\t'));
    res.json(list);
});

binary.get('/:project/:binary/code', async (req: Request, res: Response) => {
    const {addr} = req.query;
    const {project, binary} = req.params;

    const cmd =  ['./support/analyzeHeadless', 'ghidra://localhost/'+project , '-process', binary,
        '-postScript', '/opt/ghidra/custom_scripts/GhidraDecompiler.java' , addr, '-readonly', '-p']

    let out = await ghidraCmd(cmd, true);
    out = out.split('DECOMP RESULT START')[1].split('DECOMP RESULT END')[0]
        .split('GhidraDecompiler.java> ')[1].split('(GhidraScript)  \nINFO ')[0];
    res.json(out);

});
