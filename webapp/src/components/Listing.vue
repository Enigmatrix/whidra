<template>
  <table class="m-1 rounded shadow listing">
    <thead>
      <tr>
        <th>addr</th>
        <th>mne</th>
        <th>ops</th>
        <!--<th>cmt</th>-->
      </tr>
    </thead>
    <tbody>
      <tr v-for="asm in asms" :key="asm.addr">
        <td class="pl-1 address">{{asm.addr}}</td>

        <td v-if="asm.kind === 'data'" colspan="2">
          <div class="inline-flex">
          <div class="pr-2 data_value">{{asm.value}}</div>
          <div class="data_type">({{asm.type}})</div>
          </div>
        </td>

        <template v-else>
          <td class="pr-2 mnemonic">{{lower(asm.mnemonic)}}</td>
          <td>
            <pre v-for="(oper, index) in asm.operands" :key="index" class="inline-flex operand">
              <p v-for="(op, i) in oper" :key="i" :class="{[op.type]: true}">{{op.value}}</p>
              <p v-if="index+1 < asm.operands.length">,&nbsp;</p>
            </pre>
          </td>
        </template>

        <!--<td>{{asm.comments}}</td>-->
      </tr>
    </tbody>
  </table>
</template>
<script lang="ts">
import { Vue, Watch, Prop, Component } from "vue-property-decorator";
import axios from "@/axios";
import { namespace } from "vuex-class";

const BrowseStore = namespace("BrowseStore");

@Component
export default class Listing extends Vue {
  @Prop()
  public addr!: string;

  @BrowseStore.State
  public binary!: string;

  @BrowseStore.State
  public project!: string;

  public asms: any[] = [];

  public lower(str: string) {
    return str.toLowerCase();
  }

  @Watch("addr")
  public async addrChanged(addr: string | null) {
    if (!addr) {
      return;
    }
    this.asms = await axios
      .get<any[]>(`${this.project}/binary/${this.binary}/listing`, {
        params: { addr, len: 50 }
      })
      .then(x => x.data);
  }
}
</script>

<style lang="stylus">
.listing
  font-family 'Iosevka Nerd Font'
  background #1e1e1e

.address
  color #848484

.mnemonic
  color #569cd6
  font-weight bold

.data_type
  color #9cdcfe

.data_value
  color #4ec9b0
.operand > .Register
  color #ce9178
.operand > .Variable
  color #9cdcfe
.operand > .Label
  color #4EC9B0
.operand > .Scalar
  color #b5cea8;
.operand > p
  display inline
  font-family 'Iosevka Nerd Font'
</style>
