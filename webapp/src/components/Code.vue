<template>
    <code class="rounded shadow m-1 overflow-auto whitespace-pre-wrap block main-code">
        <SyntaxNode  v-if="syntaxRoot" :syntax="syntaxRoot" @selectnode="bubble"/>
    </code>
</template>
<script lang="ts">
    import {Vue, Prop, Component, Watch} from "vue-property-decorator";
    import SyntaxNode from '@/components/SyntaxNode.vue';
    import axios from "@/axios";
    import {namespace} from "vuex-class";

     const MainStore = namespace("Main");

    @Component({
        components: {
            SyntaxNode
        }
    })
    export default class Code extends Vue {
        @Prop()
        private address: number|undefined;
        @Prop()
        private fnname: string|undefined;

        @MainStore.State
        private project!: string;
        @MainStore.State
        private binary!: string;

        public syntaxRoot: Node | null = null;

        async mounted() {
            await this.onParamChanged();
        }

        @Watch('address')
        @Watch('fnname')
        async onParamChanged() {
            const resp = await axios.get<string>('/binary/code', {
                params: {
                    binary: this.binary,
                    repository: this.project,
                    addr: this.address,
                    fnName: this.fnname
                },
            });
            const parser = new DOMParser();
            const root = parser.parseFromString(resp.data, 'text/xml');
            this.syntaxRoot = root.firstChild && root.firstChild.lastChild || null;
        }

        bubble(elem: Element){
            this.$emit('selectnode', elem);
        }
    }
</script>

<style lang="stylus">
    .main-code pre
        display inline
        font-family 'Iosevka Nerd Font'
    .main-code span
        white-space nowrap
    .main-code
        background #1E1E1E
        color #D4D4D4
        font-family 'Iosevka Nerd Font'
        padding-left 1rem
    .type
        color #569cd6
    .funcname
        color #ddbb88
    .keyword
        color #ce9178
    .const
        color #b5cea8
    .comment
        color #6A9955
    .var
        color #9cdcfe
    .global
        color #4EC9B0
</style>
