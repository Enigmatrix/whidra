<template>
  <Listing
    :addr="selection && (selection.addr || selection.name)"
    id="info-listing"
  />
</template>
<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { Selection } from "@/store/browse";
import { namespace } from "vuex-class";
import Listing from "@/components/Listing.vue";

const BrowseStore = namespace("BrowseStore");
@Component({
  components: { Listing }
})
export default class Global extends Vue {
  @BrowseStore.State
  public binary!: string;

  @BrowseStore.State
  public project!: string;

  @BrowseStore.State
  public selection!: Selection | null;
}
</script>
<style lang="stylus">
#info-listing
  @apply bg-gray-800
</style>
