<template>
    <code class="overflow-auto whitespace-pre-wrap block" id="main">
        <SyntaxElem v-for="syn in syntaxes.childNodes" :syntax="syn"/>
    </code>
</template>
<script lang="ts">
import {Vue, Prop, Component, Watch} from 'vue-property-decorator';
import SyntaxElem from '../components/SyntaxElem.vue';

@Component({
    components: {
        SyntaxElem
    }
})
export default class Code extends Vue {
    @Prop({required: true}) syntaxes: Element;
}
</script>
<style>
@import url('https://fonts.googleapis.com/css?family=Source+Code+Pro&display=swap');
</style>

<style lang="stylus">
#main pre
    display inline
    font-family 'Source Code Pro Patched'

#main span
    white-space nowrap
#main
    background #1E1E1E
    color #D4D4D4
    font-family 'Source Code Pro Patched'
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

