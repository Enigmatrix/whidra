import {Router, Response, Request} from 'express';

export const projects = Router();

projects.get('/all', async (req: Request, res: Response) => {
})

projects.post('/new', async (req: Request, res: Response) => {
})

projects.get('/:project/binaries', async (req: Request, res: Response) => {
})
