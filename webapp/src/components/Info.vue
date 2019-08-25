<template>
    <div class="fixed inset-0 z-30 overflow-auto bg-smoke-light flex" v-if="currentlySelectedNode" @click.self="clearSelectedNode">
        <div class="font-code fixed bottom-0 bg-gray-700 w-full my-auto shadow-lg flex-col flex p-2 rounded-t-lg">
            <span class="font-bold text-xl" :class="classObj">{{icon}} {{currentlySelectedNode.textContent}}</span>
            <div class="border-b border-blue-700">
                <button id="rename" class=" text-sm border border-gray-600 rounded px-1 m-1 text-gray-200">RENAME &#xf8ea;</button>
                <button id="retype" v-if="nodeType !== 'type' && nodeType !== 'funcname'" class=" text-sm border border-gray-600 rounded px-1 m-1 text-gray-200">RETYPE &#xf417;</button>
                <button id="modsig" v-if="nodeType === 'funcname'" class=" text-sm border border-gray-600 rounded px-1 m-1 text-gray-200">CHANGE SIGNATURE &#xf09a;</button>
            </div>
            <div>
                {{obj}}
                <FunctionInfo v-if="nodeType === 'funcname'"></FunctionInfo>
                <ConstInfo v-else-if="nodeType === 'const'"></ConstInfo>
                <GlobalInfo v-else-if="nodeType === 'global'"></GlobalInfo>
                <TypeInfo v-else-if="nodeType === 'type'"></TypeInfo>
                <VariableInfo v-else-if="nodeType === 'var'"></VariableInfo>
            </div>
        </div>
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


const MainStore = namespace('Main');

@Component({
    components: {FunctionInfo, ConstInfo, GlobalInfo, VariableInfo, TypeInfo}
})
export default class Info extends Vue {

    @MainStore.Mutation
    private clearSelectedNode!: () => void;

    @MainStore.Getter
    private currentlySelectedNode: Element|undefined;

    get classObj() {
        return syntaxClassObj(this.currentlySelectedNode)
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
        if (!this.currentlySelectedNode) { return }
        return nodeColor(this.currentlySelectedNode);
    }

    get obj(){
        if (!this.currentlySelectedNode) { return }
        const s = new XMLSerializer();
        return s.serializeToString(this.currentlySelectedNode);
    }
}
</script>
