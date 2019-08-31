import {Func} from '@/models';
import {Module, MutationAction, Mutation, VuexModule} from 'vuex-module-decorators';
import axios from '@/axios';
import Main from '@/views/Main.vue';


export interface FuncSelection {
    function: Func;
    decompiledXml: Document;
    selectedXmlNode: Element | undefined;
}


@Module({namespaced: true})
export default class MainStore extends VuexModule {
    public project = '';
    public binary = '';
    public functions: Func[] | undefined = undefined;
    public currentFunction: Func | undefined = undefined;
    public selectedNode: Element | undefined = undefined;

    @Mutation
    public setProject(project: string) {
        this.project = project;
    }
    @Mutation
    public setBinary(binary: string) {
        this.binary = binary;
    }
    @Mutation
    public selectNode(node: Element) {
        this.selectedNode = node;
    }
    @Mutation
    public clearSelectedNode() {
        this.selectedNode = undefined;
    }
    @Mutation
    public selectFunction(func: Func) {
        this.currentFunction = func;
    }

    @MutationAction({ mutate: ['functions'] })
    public async getFunctions() {
        const state = this.state as MainStore;
        const resp = await axios.get<Func[]>('/binary/functions', {
            params: {
                binary: state.binary,
                repository: state.project,
            },
        });
        return {
            functions: resp.data,
        };
    }
}
