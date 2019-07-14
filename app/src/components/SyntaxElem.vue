<template>
    <span v-if="syntax.childNodes && syntax.childNodes.length !== 0" :class="classObj">
        <SyntaxElem v-for="syn in syntax.childNodes" :syntax="syn"/>
    </span>
    <pre v-else-if="syntax.nodeType === 3" :class="classObj" @click="click" @dblclick.native="click">{{syntax.nodeValue}}</pre>
    <pre v-else-if="syntax.nodeName === 'break'">&#10;{{'  '.repeat(+syntax.attributes.indent.value)}}</pre>
</template>
	
<script lang="ts">
import {Vue, Prop, Component, Watch} from 'vue-property-decorator';

@Component({
    name: 'SyntaxElem'
})
export default class SyntaxElem extends Vue {
    @Prop({required: true}) syntax: Node;
    get classObj(){
        const o = {};
        let tag = this.syntax.attributes ? (this.syntax.attributes.color ? this.syntax.attributes.color.value : undefined): undefined;
        o[tag] = tag;
        return o;
    }
    click(){
        this.$emit('info');
    }
    get obj(){
        const s = new XMLSerializer();
        return s.serializeToString(this.syntax);
    }
}
</script>
