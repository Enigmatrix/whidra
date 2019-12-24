import Vue from "vue";
import App from "./App.vue";
import "./registerServiceWorker";
import router from "./router";
import store from "./store";
import "./assets/tailwind.css";

import { library } from "@fortawesome/fontawesome-svg-core";
import {
  faUserSecret,
  faProjectDiagram,
  faFileCode,
  faExclamationTriangle,
  faCog
} from "@fortawesome/free-solid-svg-icons";
library.add(
  faUserSecret,
  faProjectDiagram,
  faFileCode,
  faExclamationTriangle,
  faCog
);

Vue.config.productionTip = false;

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount("#app");
