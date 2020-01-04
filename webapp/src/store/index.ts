import Vue from "vue";
import Vuex, { Store } from "vuex";
import BrowseStore from "@/store/browse";
import SessionStore from "@/store/session";

Vue.use(Vuex);

export default new Store({
  modules: {
    BrowseStore,
    SessionStore
  }
});
