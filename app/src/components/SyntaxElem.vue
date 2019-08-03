<template>
    <span v-if="syntax.childNodes && syntax.childNodes.length !== 0" :class="classObj">
        <SyntaxElem v-for="syn in syntax.childNodes" :syntax="syn"/>
    </span>
    <pre v-else-if="syntax.nodeType === 3" :class="classObj" @click="send">{{syntax.nodeValue}}</pre>
    <pre v-else-if="syntax.nodeName === 'break'">&#10;{{'  '.repeat(+syntax.attributes.indent.value)}}</pre>
</template>
	
<script lang="ts">
import {Vue, Prop, Component, Watch} from 'vue-property-decorator';
import {syntaxClassObj} from '../util/index';

@Component({
    name: 'SyntaxElem'
})
export default class SyntaxElem extends Vue {
    @Prop({required: true}) syntax!: Element;
    get classObj(){
        return syntaxClassObj(this.syntax)
    }
    send(){
        const actual = this.syntax.parentElement;
        if(actual != null && actual.nodeName !== 'syntax')
            this.$store.dispatch('selectNode', actual);
    }
    get obj(){
        const s = new XMLSerializer();
        return s.serializeToString(this.syntax);
    }
}
</script>
