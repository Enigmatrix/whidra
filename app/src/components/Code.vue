<template>
    <code class="overflow-auto whitespace-pre-wrap block" id="main">
        <SyntaxElem v-for="syn in syntaxes" :syntax="syn"/>
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
    @Prop({required: true}) syntaxes: Object;
    @Watch('syntaxes')
    onSyntaxChanged(){
        console.dir(this.syntaxes);
    }
}
</script>

<style lang="stylus">
#main pre
    display inline

#main span
    white-space nowrap
#main
    background #1E1E1E
    color #D4D4D4

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

