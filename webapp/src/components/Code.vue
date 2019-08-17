<template>
    <code class=" rounded shadow m-2 overflow-auto whitespace-pre-wrap block" id="main-code">
        <SyntaxNode :syntax="syntaxRoot"/>
    </code>
</template>
<script lang="ts">
    import {Vue, Prop, Component} from 'vue-property-decorator';
    import SyntaxNode from '@/components/SyntaxNode.vue';
    @Component({
        components: {
            SyntaxNode
        }
    })
    export default class Code extends Vue {
        @Prop({required: true}) syntaxRoot!: Element;
    }
</script>

<style lang="stylus">
    #main-code pre
        display inline
        font-family 'Iosevka Nerd Font'
    #main-code span
        white-space nowrap
    #main-code
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
