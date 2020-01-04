<template>
  <Page>
    <div slot="nav">
      <div class="text-lg">
        <a href="/" class="text-blue-500">{{ project }}</a>
        <span class="mx-1">/</span>
        <a :href="`/browse/${project}/${binary}`" class="text-blue-500">{{
          binary
        }}</a>
      </div>
    </div>

    <div slot="side" class="w-full">
      <div
        v-for="fn in normalFunctions"
        :key="fn.address"
        @click="selectFunction(fn)"
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

    <VueTabs>
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
        <div>sorry wga</div>
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
  </Page>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
// @ts-ignore
import { VueTabs, VTab } from "vue-nav-tabs";
import "vue-nav-tabs/themes/vue-tabs.css";
import Page from "@/components/Page.vue";
import { Function } from "@/models/response";
import { namespace } from "vuex-class";
import { CurrentFunctionDetail } from "@/store/browse";
import Code from "@/components/Code.vue";

const BrowseStore = namespace("BrowseStore");

@Component({
  components: {Code, FontAwesomeIcon, Page, VueTabs, VTab }
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

  async mounted() {
    await this.load({ project: this.project, binary: this.binary });
  }
}
</script>

<style lang="stylus">
.nav-tabs
  @apply flex

.tab
  @apply flex-1 text-center
  @apply bg-gray-900 text-gray-300

.vue-tabs .nav-tabs > li.active > a
.vue-tabs .nav-tabs > li.active > a:hover
.vue-tabs .nav-tabs > li.active > a:focus
  @apply bg-gray-800 text-gray-100
  @apply border-gray-800
</style>
