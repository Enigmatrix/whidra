<template>
  <Code :syntax-tree="functionSyntaxTree" id="info-code" />
</template>
<script lang="ts">
import { Component, Prop, Vue, Watch } from "vue-property-decorator";
import Code from "@/components/Code.vue";
import { Selection, SelectionType } from "@/store/browse";
import { functionXml } from "@/util";
import { namespace } from "vuex-class";

const BrowseStore = namespace("BrowseStore");

@Component({
  components: { Code }
})
export default class Function extends Vue {
  @BrowseStore.State
  public binary!: string;

  @BrowseStore.State
  public project!: string;

  @BrowseStore.State
  public selection!: Selection | null;

  public functionSyntaxTree: null | ChildNode = null;

  @Watch("selection", { immediate: true })
  async watchSyntaxTree(selection: Selection) {
    window.console.log(selection);
    if (selection.type !== SelectionType.Function) return;
    const { syntaxTree } = await functionXml(
      this.project,
      this.binary,
      undefined,
      selection.name || undefined
    );
    window.console.log(syntaxTree);
    this.functionSyntaxTree = syntaxTree;
  }
}
</script>
<style lang="stylus">
#info-code
  @apply bg-gray-800
</style>
