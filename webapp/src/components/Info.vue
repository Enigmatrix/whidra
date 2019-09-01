<template>
    <div class="fixed inset-0 z-30 overflow-auto bg-smoke-light flex" v-if="selectedNode" @click.self="clearSelectedNode">
        <div class="font-code infobox fixed bottom-0 bg-blue-900 w-full my-auto shadow-lg flex-col flex rounded-t-lg">
            <button class="font-bold text-xl px-2 pt-2 inline-flex" :class="classObj">{{icon}} {{selectedNode.textContent}} &#xf8cb;</button>
            <div class="border-b border-blue-700 px-2">
                <button id="rename" class=" text-sm border border-gray-600 rounded px-1 m-1 text-gray-200" @click="rename">RENAME &#xf8ea;</button>
                <button id="retype" v-if="nodeType !== 'type' && nodeType !== 'funcname'" class=" text-sm border border-gray-600 rounded px-1 m-1 text-gray-200">RETYPE &#xf417;</button>
                <button id="modsig" v-if="nodeType === 'funcname'" class=" text-sm border border-gray-600 rounded px-1 m-1 text-gray-200">CHANGE SIGNATURE &#xf09a;</button>
            </div>
            <div class="overflow-auto m-1">
                <FunctionInfo v-if="nodeType === 'funcname'"></FunctionInfo>
                <ConstInfo v-else-if="nodeType === 'const'"></ConstInfo>
                <GlobalInfo v-else-if="nodeType === 'global'"></GlobalInfo>
                <TypeInfo v-else-if="nodeType === 'type'"></TypeInfo>
                <VariableInfo v-else-if="nodeType === 'var'"></VariableInfo>
            </div>
        </div>

        <Modal ref="renameModal" :title="'RENAME '+adjustedNodeType.toUpperCase()" @submit="renameSubmit">
            <input required class="bg-gray-700 my-2 font-code text-xl appearance-none p-2" placeholder="NEW NAME" name="newName">
            <button type="submit" class="bg-blue-500 rounded p-2 mt-2 font-bold">SUBMIT</button>
        </Modal>
    </div>
</template>
<script lang="ts">
import {Component, Prop, Vue} from 'vue-property-decorator';
import {namespace} from 'vuex-class';
import {nodeColor, syntaxClassObj} from "@/util";
import FunctionInfo from './FunctionInfo.vue';
import ConstInfo from './ConstInfo.vue';
import GlobalInfo from './GlobalInfo.vue';
import VariableInfo from './VariableInfo.vue';
import TypeInfo from './TypeInfo.vue';
import Modal from './Modal.vue';
import {Func} from "@/models";
import axios from '@/axios';


const MainStore = namespace('Main');

@Component({
    components: {FunctionInfo, ConstInfo, GlobalInfo, VariableInfo, TypeInfo, Modal}
})
export default class Info extends Vue {

    public $refs!: {
        renameModal: any;
    };

    @MainStore.Mutation
    private clearSelectedNode!: () => void;

    @MainStore.State
    private project!: string;

    @MainStore.State
    private binary!: string;

    @MainStore.State
    private currentFunction!: Func | undefined;

    @MainStore.State
    private selectedNode!: Element;

    rename() {
        this.$refs.renameModal.open();
    }

    async renameSubmit(form: FormData) {
        form.append('repository', this.project);
        form.append('binary', this.binary);
        const type = this.adjustedNodeType;
        if(this.currentFunction) {
            form.append('fnAddr', this.currentFunction.addr.toString());
        }
        switch(type) {
            case 'symbol':
                form.append('oldSymName', this.selectedNode.textContent!);
                break;
            case 'variable':
                form.append('oldVarName', this.selectedNode.textContent!);
                break;
        }
        await axios.post(`refactor/rename/${type}`, form);
    }

    get classObj() {
        return syntaxClassObj(this.selectedNode)
    }

    get icon() {
        switch(this.nodeType){
            case 'funcname':
                return '\uf09a';
            case 'type':
                return '\uf417';
            case 'var':
                return '\ue79b';
            case 'const':
                return '\uf1de';
            case 'global':
                return '\uf0e8';
            case 'keyword':
                return '\uf1de';
            default:
                return '';
        }
    }

    get nodeType() {
        if (!this.selectedNode) { return }
        return nodeColor(this.selectedNode);
    }

    get adjustedNodeType() {
        switch (this.nodeType) {
            case 'var':
                return 'variable';
            case 'funcname':
                return 'function';
            case 'global':
                return 'symbol';
            default:
                return '';
        }
    }

    get obj(){
        if (!this.selectedNode) { return }
        const s = new XMLSerializer();
        return s.serializeToString(this.selectedNode);
    }
}
</script>
<style lang="stylus">
    .infobox
        max-height 50%;
</style>
