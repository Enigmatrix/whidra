<template>
    <span v-if="syntax.childNodes && syntax.childNodes.length !== 0" :class="classObj">
        <SyntaxNode v-for="syn in syntax.childNodes" :syntax="syn" @selectnode="bubble"/>
    </span>
    <pre v-else-if="syntax.nodeType === 3" :class="classObj" @click="send">{{syntax.nodeValue}}</pre>
    <pre v-else-if="syntax.nodeName === 'break'">&#10;{{'  '.repeat(+syntax.attributes.indent.value)}}</pre>
</template>

<script lang="ts">
    import {Vue, Prop, Component} from 'vue-property-decorator';
    import {syntaxClassObj} from '@/util';

    @Component({
        name: 'SyntaxNode'
    })
    export default class SyntaxNode extends Vue {
        @Prop({required: true}) syntax!: Element;

        get classObj(){
            return syntaxClassObj(this.syntax)
        }

        send(){
            const actual = this.syntax.parentElement;

            if(actual != null && actual.nodeName !== 'syntax'){
                this.$emit('selectnode', actual);
            }
        }

        bubble(elem: Element){
            this.$emit('selectnode', elem);
        }

        // for debugging purposes
        get obj(){
            const s = new XMLSerializer();
            return s.serializeToString(this.syntax);
        }
    }
</script>
