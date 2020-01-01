<template>
  <Page>
    <div slot="nav">
      <div class="text-lg">
        <a href="/" class="text-blue-500">{{project}}</a>
        <span class="mx-1">/</span>
        <a :href="`/browse/${project}/${binary}`" class="text-blue-500">{{binary}}</a>
      </div>
    </div>

    <div slot="side">
      <div v-for="fn in functions" :key="fn.address">
        <div>{{fn.name}}</div>
        <div>{{fn.signature}}</div>
        <div>{{fn.addresss}}</div>
      </div>
    </div>

    <VueTabs>
      <VTab title="code">
        <div slot="title" class="flex flex-row justify-center">
          <FontAwesomeIcon icon="code" class="self-center" />
          <div class="w-2"></div>
          <div>CODE</div>
        </div>
        <div>{{project}}/{{binary}}</div>
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
import axios from '../axios';

@Component({
  components: { FontAwesomeIcon, Page, VueTabs, VTab }
})
export default class Browse extends Vue {
  @Prop({ required: true })
  public project!: string;
  @Prop({ required: true })
  public binary!: string;

  public functions: Function[]|null = null;

  async mounted() {
    this.functions = await axios
      .get<Function[]>(`${this.project}/binary/${this.binary}/functions`).then(x => x.data);
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
