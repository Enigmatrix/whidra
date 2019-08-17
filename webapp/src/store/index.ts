import Vue from 'vue';
import Vuex, { Store } from 'vuex';
import Main from './main';

Vue.use(Vuex);

export default new Store({
  modules: {
    Main,
  },
});
