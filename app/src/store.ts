import Vue from 'vue';
import Vuex from 'vuex';
import axios from './axios';

Vue.use(Vuex);

type Func = [string, string];

interface StoreProps {
    root: Document | undefined;
    project: string;
    binary: string;
    functions: Func[];
    selectedNode: Element | undefined;
    infoOpen: boolean;
}

export default new Vuex.Store<StoreProps>({
  state: {
    root: undefined,
    project: '',
    binary: '',
    functions: [],
    selectedNode: undefined,
    infoOpen: false
  },
  getters: {
    syntax: (state) => {
        return state.root && state.root.firstChild &&
            state.root.firstChild.lastChild || undefined;
    },
  },
  mutations: {
      setPre: (state, {binary, project}) => {
          state.project = project;
          state.binary = binary;
      },
      setRoot: (state, newRoot) => {
          Vue.set(state, 'root', newRoot);
      },
      setFunctions: (state, newFunctions) => {
          Vue.set(state, 'functions', newFunctions);
      },
      setSelectedNode: (state, node: Element) => {
          state.selectedNode = node;
          state.infoOpen = true;
      },
      infoClose: (state) => {
          state.infoOpen = false;
      }
  },
  actions: {
    getFunctions: async ({commit, state}) => {
      const url = `/binary/${state.project}/${state.binary}/functions`;
      const functions = await axios.get<Func[]>(url).then((x) => x.data);
      commit('setFunctions', functions);
    },
    setFunction: async ({commit, state}, address) => {
      const url = `/binary/${state.project}/${state.binary}/code`;
      const params = { params: {addr: address.split('0x')[1] } };
      const xml = await axios.get<string>(url, params).then((x) => x.data);
      const xp = new DOMParser();
      commit('setRoot', xp.parseFromString(xml, 'text/xml'));
    },
    selectNode: async ({commit, state}, node) => {
      commit('setSelectedNode', node);
    }
  }
})
