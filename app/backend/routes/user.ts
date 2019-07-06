import {Router, Request, Response} from 'express';

export const user = Router();

user.post('/login', async (req: Request, res: Response) => {
    //TODO complete this thing
    console.log(req.body);
    res.redirect('/projects');
});
