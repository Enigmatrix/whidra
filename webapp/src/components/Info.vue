import {SelectionType} from "@/store/browse";
<template>
  <div
    class="absolute bottom-0 top-0 right-0 left-0 info font-code"
    v-if="selection"
    @click.self="unselect"
  >
    <div
      class="absolute bottom-0 left-0 right-0 bg-blue-900 rounded-t-lg shadow flex flex-col info-box "
    >
      <div class="border-b border-blue-800 p-2 info-header">
        <span :class="classObj">
          <span class="px-2">{{ icon }}</span>
          <span class="font-bold">{{ selection.name }}</span>
        </span>
        <FontAwesomeIcon icon="external-link-alt" class="mx-2 text-gray-400" />
      </div>
      <div class="flex-1 info-content p-2 overflow-auto">
        <Const v-if="isConst" />
        <Function v-else-if="isFunction" />
      </div>
    </div>
  </div>
</template>
<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { namespace } from "vuex-class";
import {
  CurrentFunctionDetail,
  Selection,
  SelectionType
} from "@/store/browse";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { selectionToClassObj } from "@/util";
import Code from "@/components/Code.vue";
import Function from "@/components/info/Function.vue";
import Const from "@/components/info/Const.vue";

const BrowseStore = namespace("BrowseStore");

@Component({
  components: { Const, Function, Code, FontAwesomeIcon }
})
export default class Info extends Vue {
  @BrowseStore.State
  public binary!: string;

  @BrowseStore.State
  public project!: string;

  @BrowseStore.State
  public selection!: Selection | null;

  @BrowseStore.State
  public current!: CurrentFunctionDetail | null;

  @BrowseStore.Mutation
  public select!: (selection: Selection | null) => void;

  public unselect() {
    this.select(null);
  }

  get classObj() {
    if (!this.selection) return null;
    return selectionToClassObj(this.selection.type);
  }

  get isConst() {
    return this.selection && this.selection.type === SelectionType.Const;
  }

  get isGlobal() {
    return this.selection && this.selection.type === SelectionType.Global;
  }

  get isVariable() {
    return this.selection && this.selection.type === SelectionType.Variable;
  }

  get isType() {
    return this.selection && this.selection.type === SelectionType.Type;
  }

  get isFunction() {
    return this.selection && this.selection.type === SelectionType.Function;
  }

  get icon() {
    switch (this.selection && this.selection.type) {
      case SelectionType.Function:
        return "\uf09a";
      case SelectionType.Type:
        return "\uf417";
      case SelectionType.Variable:
        return "\ue79b";
      case SelectionType.Const:
        return "\uf1de";
      case SelectionType.Global:
        return "\uf0e8";
      default:
        return "?";
    }
  }

}
</script>
<style lang="stylus">
.info-box
  max-height 50%

.info
  background rgba(0, 0, 0, 0.4)

.const-vals
  text-align left
  td
    @apply px-2
</style>
