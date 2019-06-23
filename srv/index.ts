import express, {Application, json} from 'express';

const routes = async (path: string) => import(path).then((mod) => mod.default);

export default async (app: Application) => {
  app.use(json());

  app.use('/api/chall', await routes('./routes/chall'));
};
