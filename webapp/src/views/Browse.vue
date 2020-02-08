<template>
  <Page>
    <div slot="nav">
      <div class="text-lg">
        <router-link :to="{ name: 'home' }" class="text-blue-500">{{
          project
        }}</router-link>
        <span class="mx-1">/</span>
        <router-link
          :to="{
            name: 'browse',
            params: { binary, project }
          }"
          class="text-blue-500"
          >{{ binary }}</router-link
        >
      </div>
    </div>

    <div slot="side" class="w-full">
      <div
        v-for="fn in normalFunctions"
        :key="fn.address"
        @click="selectFunctionClick(fn)"
        class="flex border-t border-blue-700 px-2 py-1"
        :class="{ 'bg-blue-700': current && fn === current.function }"
      >
        <div>
          <div class="font-bold">{{ fn.name }}</div>
          <div class="ml-2 text-sm">{{ fn.signature }}</div>
        </div>
        <div class="flex-1"></div>
        <div class="self-center">{{ fn.addr }}</div>
      </div>
    </div>

    <VueTabs class="absolute left-0 right-0 bottom-0">
      <VTab title="code">
        <div slot="title" class="flex flex-row justify-center">
          <FontAwesomeIcon icon="code" class="self-center" />
          <div class="w-2"></div>
          <div>CODE</div>
        </div>
        <Code :syntax-tree="current && current.syntaxTree" />
      </VTab>
      <VTab title="asm">
        <div slot="title" class="flex flex-row justify-center">
          <FontAwesomeIcon icon="list" class="self-center" />
          <div class="w-2"></div>
          <div>ASM</div>
        </div>
        <Listing :addr="current && current.function.addr" />
      </VTab>
      <VTab title="term">
        <div slot="title" class="flex flex-row justify-center">
          <FontAwesomeIcon icon="terminal" class="self-center" />
          <div class="w-2"></div>
          <div>TERM</div>
        </div>
        <div>sorry wga</div>
      </VTab>
    </VueTabs>

    <Info />
  </Page>
</template>

<script lang="ts">
import { Component, Vue, Prop, Watch } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
// @ts-ignore
import { VueTabs, VTab } from "vue-nav-tabs";
import "vue-nav-tabs/themes/vue-tabs.css";
import Page from "@/components/Page.vue";
import { Function } from "@/models/response";
import { namespace } from "vuex-class";
import { CurrentFunctionDetail } from "@/store/browse";
import Code from "@/components/Code.vue";
import Listing from "@/components/Listing.vue";
import Info from "@/components/Info.vue";
import { Route } from "vue-router";

const BrowseStore = namespace("BrowseStore");

@Component({
  components: { Info, Listing, Code, FontAwesomeIcon, Page, VueTabs, VTab }
})
export default class Browse extends Vue {
  @Prop({ required: true })
  public project!: string;
  @Prop({ required: true })
  public binary!: string;

  @BrowseStore.Getter
  public normalFunctions!: Function[];

  @BrowseStore.Getter
  public thunkedFunctions!: Function[];

  @BrowseStore.State
  public current!: CurrentFunctionDetail | null;

  @BrowseStore.Action
  public load!: (binary: { project: string; binary: string }) => Promise<void>;

  @BrowseStore.Action
  public selectFunction!: (func: Function) => Promise<void>;

  public selectFunctionClick(func: Function) {
    this.$router.push({
      name: "browse",
      params: { project: this.project, binary: this.binary },
      query: { fnname: func.name }
    });
  }

  @Watch("$route", { immediate: true })
  async routeWatcher(to: Route, from: Route) {
    if (to.name !== "browse") return;
    await this.selectFunctionBase(to.query.fnname as string);
  }

  public async selectFunctionBase(fnname: string | undefined) {
    let fn: Function | undefined;
    if (fnname && fnname.length !== 0) {
      fn = this.normalFunctions.find(x => x.name === fnname);
    }
    if (!fn) {
      fn = this.normalFunctions.find(x => x.name === "main");
    }
    if (!fn) {
      fn = this.normalFunctions[0];
    }
    if (fn) {
      await this.selectFunction(fn);
    }
  }

  async mounted() {
    await this.load({ project: this.project, binary: this.binary });
    await this.selectFunctionBase(this.$route.query.fnname as string);
  }
}
</script>

<style lang="stylus">
.nav-tabs
  @apply flex

.vue-tabs
  top 3rem

.tab
  @apply flex-1 text-center
  @apply bg-gray-900 text-gray-300

.tab-container
  height 100%
  min-height 0

.tab-content
  height 100%
  min-height 0

.vue-tabs .nav-tabs > li.active > a
.vue-tabs .nav-tabs > li.active > a:hover
.vue-tabs .nav-tabs > li.active > a:focus
  @apply bg-gray-800 text-gray-100
  @apply border-gray-800
</style>
