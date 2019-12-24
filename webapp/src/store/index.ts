import Vue from "vue";
import Vuex, { Store } from "vuex";
import CodeBrowserStore from "@/store/codebrowser";

Vue.use(Vuex);

export default new Store({
  modules: {
    CodeBrowserStore
  }
});
