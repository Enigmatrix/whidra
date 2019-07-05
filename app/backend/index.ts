import {Application, json} from 'express';

export default (app: Application, http) => {
  app.use(json());
}
