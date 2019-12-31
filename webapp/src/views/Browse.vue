<template>
  <Page>
    <Tabs>
      <Tab>
        <div slot="title">lmao</div>
        <div>sorry wga</div>
      </Tab>
    </Tabs>
  </Page>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import Page from "@/components/Page.vue";

@Component({
  components: { FontAwesomeIcon, Page }
})
export default class Browse extends Vue {
  private project!: string;
  private binary!: string;


}
</script>

<style lang="stylus">

</style>
