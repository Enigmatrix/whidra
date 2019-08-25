<template>
    <span v-if="syntax.childNodes && syntax.childNodes.length !== 0" :class="classObj">
        <SyntaxNode v-for="syn in syntax.childNodes" :syntax="syn"/>
    </span>
    <pre v-else-if="syntax.nodeType === 3" :class="classObj" @click="send">{{syntax.nodeValue}}</pre>
    <pre v-else-if="syntax.nodeName === 'break'">&#10;{{'  '.repeat(+syntax.attributes.indent.value)}}</pre>
</template>

<script lang="ts">
    import {Vue, Prop, Component} from 'vue-property-decorator';
    import {syntaxClassObj} from '@/util';
    import {namespace} from 'vuex-class';

    const MainStore = namespace('Main');
    @Component({
        name: 'SyntaxNode'
    })
    export default class SyntaxNode extends Vue {
        @Prop({required: true}) syntax!: Element;
        @MainStore.Mutation
        private selectNode!: (s: Element) => void;
        get classObj(){
            return syntaxClassObj(this.syntax)
        }
        send(){
            const actual = this.syntax.parentElement;

            if(actual != null && actual.nodeName !== 'syntax')
                this.selectNode(actual)
        }
        // for debugging purposes
        get obj(){
            const s = new XMLSerializer();
            return s.serializeToString(this.syntax);
        }
    }
</script>
