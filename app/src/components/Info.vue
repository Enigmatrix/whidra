<template>
        <div class="fixed inset-0 z-40 overflow-auto bg-smoke-light flex" v-if="infoOpen" @click.self="infoClose()">
            <div class="absolute min-w-full bottom-0 bg-gray-800 h-8/12 m-auto flex-col flex p-4 shadow-lg">
                <span id="title" class="font-bold text-2xl mb-4" :class="classObj">{{icon}}&nbsp;{{selectedNode.childNodes[0].nodeValue}}</span>
            <div class="flex flex-col">
                <span>{{serialize(selectedNode)}}</span>
                <span v-if="selectedNode.attributes['varref'] !== undefined">{{serialize(highVarref)}}</span>
            </div>
            </div>
        </div>
	
</template>
<script lang="ts">
import {Component, Vue, Prop} from 'vue-property-decorator';
import {mapState, mapMutations, mapActions, mapGetters} from 'vuex';
import { syntaxClassObj, nodeColor } from '../util';

@Component({
    computed: { ...mapState(['selectedNode', 'infoOpen', 'root']) },
    methods: { ...mapMutations(['setPre', 'infoClose']) }
})
export default class Info extends Vue {

    selectedNode!: Element;
    root!: Element;

    serialize(node: Element){
        if(!node) return 'no highref';
        return new XMLSerializer().serializeToString(node);
    }
    get classObj(){
        return syntaxClassObj(this.selectedNode);
    }

    get icon() {
        switch(nodeColor(this.selectedNode)){
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
    get highVarref() {
        const varref = this!.selectedNode!.attributes.getNamedItem('varref')!.value;
        return this.root.querySelector(`high[repref="${varref}"]`)
    }
}
</script>

<style lang="stylus">
#title
    font-family 'Source Code Pro Patched'
</style>
