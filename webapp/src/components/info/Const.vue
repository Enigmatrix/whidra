import {SelectionType} from "@/store/browse";
<template>
  <table class="const-vals">
    <tbody>
      <tr>
        <th>Hex:</th>
        <td>{{ hex(constValue) }}</td>
      </tr>
      <tr>
        <th>Dec:</th>
        <td>{{ constValue }}</td>
      </tr>
      <tr>
        <th>Oct:</th>
        <td>{{ oct(constValue) }}</td>
      </tr>
      <tr>
        <th>Bin:</th>
        <td>{{ bin(constValue) }}</td>
      </tr>
    </tbody>
  </table>
</template>
<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import {
  CurrentFunctionDetail,
  Selection,
  SelectionType
} from "@/store/browse";
import { namespace } from "vuex-class";

const BrowseStore = namespace("BrowseStore");

@Component
export default class Const extends Vue {
  @BrowseStore.State
  public binary!: string;

  @BrowseStore.State
  public project!: string;

  @BrowseStore.State
  public selection!: Selection | null;

  @BrowseStore.State
  public current!: CurrentFunctionDetail | null;

  get constValue() {
    if (
      !this.current ||
      !this.selection ||
      !(this.selection.origin instanceof Element) ||
      this.selection.type !== SelectionType.Const
    )
      return null;

    const varref = this.selection.origin.getAttribute("varref");
    const varnode = this.current.ast.querySelector(`[ref='${varref}']`);
    if (!varnode) return null;
    const address = varnode.getAttribute("offset");
    if (!address) return null;
    return parseInt(address, 16);
  }

  public hex(v: number) {
    return "0x" + v.toString(16);
  }

  public oct(v: number) {
    return "0o" + v.toString(8);
  }

  public bin(v: number) {
    return "0b" + v.toString(2);
  }
}
</script>
<style lang="stylus">
.const-vals
  text-align left
  td
    @apply px-2
</style>
