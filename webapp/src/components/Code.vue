<template>
  <code
    class="rounded shadow m-1 overflow-auto whitespace-pre-wrap block main-code"
  >
    <SyntaxNode v-if="syntaxTree" :syntax="syntaxTree" />
  </code>
</template>
<script lang="ts">
import { Vue, Prop, Component } from "vue-property-decorator";
import SyntaxNode from "@/components/SyntaxNode.vue";
import { namespace } from "vuex-class";

const MainStore = namespace("Main");

@Component({
  components: {
    SyntaxNode
  }
})
export default class Code extends Vue {
  @Prop()
  public syntaxTree!: Document | null;
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
