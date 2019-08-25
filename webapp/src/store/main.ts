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
    public currentFunction: FuncSelection | undefined = undefined;

    get currentFunctionSyntaxTree() {
        if (!this.currentFunction) { return undefined; }
        const root = this.currentFunction.decompiledXml;
        return root.firstChild && root.firstChild.lastChild || undefined;
    }
    get currentlySelectedNode(){
        if (!this.currentFunction) { return undefined; }
        return this.currentFunction.selectedXmlNode;
    }

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
        if (!this.currentFunction) { return; }
        this.currentFunction.selectedXmlNode = node;
    }
    @Mutation clearSelectedNode(){
        if (!this.currentFunction) { return; }
        this.currentFunction.selectedXmlNode = undefined;
    }

    @MutationAction({ mutate: ['currentFunction'] })
    public async selectFunction(func: Func) {
        const state = this.state as MainStore;
        const resp = await axios.get<string>('/binary/code', {
            params: {
                binary: state.binary,
                repository: state.project,
                addr: func.addr,
            },
        });
        const parser = new DOMParser();
        const doc = parser.parseFromString(resp.data, 'text/xml');
        return {
            currentFunction: {
                function: func,
                decompiledXml: doc,
                selectedXmlNode: undefined,
            },
        };
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
