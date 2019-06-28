import express, {Application, json} from 'express';
import chall from './routes/chall';


export default async (app: Application) => {
  app.use(json());
  app.use('/api/chall', chall);
};
