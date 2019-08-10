import Vue from 'vue';
import Router from 'vue-router';
import Projects from '@/views/Projects.vue';
import Home from '@/views/Home.vue';

Vue.use(Router);

export default new Router({
  mode: 'history',
  base: process.env.BASE_URL,
  routes: [
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
