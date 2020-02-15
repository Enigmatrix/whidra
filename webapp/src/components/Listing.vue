<template>
  <table
    ref="listing"
    class="m-1 rounded shadow table-fixed listing max-h-full min-h-0 block overflow-scroll"
    @scroll="scroll"
  >
    <thead>
      <tr class="hidden">
        <th>addr</th>
        <th class="relative">mne</th>
        <th class="w-full">ops</th>
        <!--<th>cmt</th>-->
      </tr>
    </thead>
    <tbody>
      <ListingLine v-for="asm in asms" :key="asm.addr" :asm="asm" />
    </tbody>
  </table>
</template>
<script lang="ts">
import { Vue, Watch, Prop, Component } from "vue-property-decorator";
import axios from "@/axios";
import { namespace } from "vuex-class";
import ListingLine from "@/components/ListingLine.vue";
import { debounce } from "@/util";

const BrowseStore = namespace("BrowseStore");
@Component({
  components: { ListingLine }
})
export default class Listing extends Vue {
  public $refs!: {
    listing: HTMLTableElement;
  };

  @Prop()
  public addr!: string;

  @BrowseStore.State
  public binary!: string;

  @BrowseStore.State
  public project!: string;

  public asms: any[] = [];

  public scrollHandler = debounce(this.scroll, 200).bind(this);

  public async scroll() {
    const listing = this.$refs.listing;
    const end = listing.scrollHeight - listing.clientHeight;
    if (listing.scrollTop === 0) {
      await this.loadPrepend();
    } else if (listing.scrollTop === end) {
      await this.loadAppend();
    }
    //window.console.log(listing.scrollTop, end);
  }

  public async loadPrepend() {
    window.console.info("PREPEND");
  }

  public async loadAppend() {
    window.console.info("APPEND");
    let result = this.asms;
    const len = result.length;
    result = result.slice(len / 2, len);

    const newItems = await this.load(this.asms[this.asms.length - 1].addr, len / 2);
    result = result.concat(newItems);

    const listing = this.$refs.listing;
    const end = listing.scrollHeight - listing.clientHeight;
    listing.scroll(0, end - 1);

    this.asms = result;
    listing.scroll(0, end / 2);
  }

  public async load(addr: string, len: number): Promise<any[]> {
    return await axios
      .get<any[]>(`${this.project}/binary/${this.binary}/listing`, {
        params: { addr, len }
      })
      .then(x => x.data);
  }

  @Watch("addr", { immediate: true })
  public async addrChanged(addr: string | null) {
    if (!addr) {
      return;
    }
    this.asms = await this.load(addr, 50);
  }
}
</script>

<style lang="stylus">
.listing
  font-family 'Iosevka Nerd Font'
  background #1e1e1e
/*  -ms-overflow-style none
  overflow-y -moz-scrollbars-none

.listing::-webkit-scrollbar {
  width 0 !important
} */

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
