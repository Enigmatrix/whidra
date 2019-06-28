import {Router, Request, Response} from 'express';

const challs = Router();

challs.post('/upload', async (req: Request, res: Response) => {
    res.json({ status: 'online' });
});

challs.get('/code', async (req: Request, res: Response) => {
    res.json({ status: 'online' });
});

challs.get('/asm', async (req: Request, res: Response) => {
    res.json({ status: 'online' });
});

export default challs;
