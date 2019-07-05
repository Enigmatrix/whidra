import Vue from 'vue';
import Router from 'vue-router';
import Home from './views/Home.vue';
import Projects from './views/Projects.vue';
import Code from './views/Code.vue';

Vue.use(Router);

export default new Router({
  mode: 'history',
  base: process.env.BASE_URL,
  routes: [
    {
      path: '/',
      name: 'home',
      component: Home,
    },
      {
          path: '/projects',
          name: 'projects',
          component: Projects,
      },
      {
          path: '/:project/:binary',
          name: 'code',
          component: Code,
      },
    {
      path: '/about',
      name: 'about',
      // route level code-splitting
      // this generates a separate chunk (about.[hash].js) for this route
      // which is lazy-loaded when the route is visited.
      component: () => import(/* webpackChunkName: "about" */ './views/About.vue'),
    },
  ],
});
