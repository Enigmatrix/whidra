<template>
  <div>
    {{ addr }}
    <div v-for="(asm, i) in asms" :key="i">{{ asm }}</div>
  </div>
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

  public asms: string[] = [];

  @Watch("addr")
  public async addrChanged(addr: string|null) {
    if (!addr) {
      return;
    }
    this.asms = await axios.get<string[]>(
      `${this.project}/binary/${this.binary}/listing`,
      {
        params: { addr, len: 50 }
      })
      .then(x => x.data);
  }
}
</script>

<style lang="stylus"></style>
