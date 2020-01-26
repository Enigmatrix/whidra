import Vue from "vue";
import App from "./App.vue";
import "./registerServiceWorker";
import router from "./router";
import store from "./store";
import "./assets/tailwind.css";
import VModal from "vue-js-modal";
Vue.use(VModal);

import { library } from "@fortawesome/fontawesome-svg-core";
import {
  faUserSecret,
  faProjectDiagram,
  faFileCode,
  faExclamationTriangle,
  faCog,
  faUpload,
  faPlus,
  faBars,
  faHome,
  faCode,
  faTerminal,
  faList,
  faExternalLinkAlt
} from "@fortawesome/free-solid-svg-icons";
library.add(
  faUserSecret,
  faProjectDiagram,
  faFileCode,
  faExclamationTriangle,
  faCog,
  faUpload,
  faPlus,
  faBars,
  faHome,
  faCode,
  faTerminal,
  faList,
  faExternalLinkAlt
);

Vue.config.productionTip = false;

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount("#app");
