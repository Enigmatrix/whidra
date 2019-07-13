import {Router, Response, Request} from 'express';
import {promisify} from 'util';
import {exists, unlink} from 'fs';
import {ghidraCmd} from '../ghidra';

export const upload = Router();

const fileExists = promisify(exists);
const fileDelete = promisify(unlink);

upload.post('/:project', async (req: Request, res: Response) => {
    const {binary} = req.files;
    const {project} = req.params;
    if (!binary) {
        res.status(400).send('No file uploaded!');
        return;
    }
    if (binary instanceof Array) {
        res.status(400).send('One file only, please');
        return;
    }
    const newPath = '/uploads/' + binary.name;
    if (await fileExists(newPath)) {
        res.status(400).send('Seems like the file exists?');
        return;
    }
    await promisify(binary.mv).bind(binary)(newPath);
    const cmd = ['./support/analyzeHeadless', 'ghidra://localhost/' + project, '-import', newPath, '-noanalysis', '-p']
    await ghidraCmd(cmd, true);
    await fileDelete(newPath);
    res.redirect('/projects');
});
