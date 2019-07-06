import {Application, json} from 'express';
import {user} from './routes/user';
import {urlencoded} from 'body-parser';
import {projects} from './routes/projects';

export default (app: Application, http) => {
  app.use(json());
  app.use(urlencoded({extended: true}));

  app.use('/api/user', user);
  app.use('/api/projects', projects);
}
