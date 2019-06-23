import express, {Request, Response} from 'express';

const challs = express.Router();

challs.post('/upload', async (req: Request, res: Response) => {
    res.json({ status: 'fail' });
});

export default challs;
