import Vue from "vue";
import VueRouter from "vue-router";
import Home from "../views/Home.vue";
import store from "@/store";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    name: "home",
    meta: { requiresAuthentication: true },
    component: Home
  },
  {
    path: "/login",
    name: "login",
    meta: { requiresAuthentication: false },
    component: () =>
      import(/* webpackChunkName: "project" */ "../views/Login.vue")
  },
  {
    path: "/browse/:project/:binary",
    name: "code",
    meta: { requiresAuthentication: true },
    props: true,
    component: () =>
      import(/* webpackChunkName: "code" */ "../views/Browse.vue")
  }
];

const router = new VueRouter({
  mode: "history",
  base: process.env.BASE_URL,
  routes
});

router.beforeEach(async (to, _, next) => {
  await store.dispatch("SessionStore/checkAuthenticated");

  if (!to.meta.requiresAuthentication) {
    next();
    return;
  }

  if (!store.getters["SessionStore/authenticated"]) {
    next("/login");
  } else {
    next();
  }
});

export default router;
