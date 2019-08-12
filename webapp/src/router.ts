import Vue from 'vue';
import Router from 'vue-router';
import Projects from '@/views/Projects.vue';
import Home from '@/views/Home.vue';
import Main from '@/views/Main.vue';

Vue.use(Router);

export default new Router({
  mode: 'history',
  base: process.env.BASE_URL,
  routes: [
    {
      path: '/:project/:binary',
      name: 'main',
      component: Main,
      props: true
    },
    {
      path: '/projects',
      name: 'projects',
      component: Projects,
    },
    {
      path: '/',
      name: 'home',
      component: Home,
    },
  ],
});
