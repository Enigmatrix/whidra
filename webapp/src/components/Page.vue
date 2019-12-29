<template>
  <div class="min-h-screen flex flex-col">
    <DrawerLayout :animatable="true" :backdrop="true" @mask-click="closeSide" ref="drawer">
      <div class="drawer-content" slot="drawer">
        <SideBar>
          <slot name="side" />
        </SideBar>
      </div>

      <div class="flex flex-1 flex-col" slot="content">
        <NavBar @menu-click="openSide">
          <slot name="nav" />
        </NavBar>
        <slot />
      </div>
    </DrawerLayout>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import NavBar from "@/components/NavBar.vue";
import SideBar from "@/components/SideBar.vue";
import { DrawerLayout } from "vue-drawer-layout";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";

@Component({
  components: { NavBar, SideBar, DrawerLayout, FontAwesomeIcon }
})
export default class Page extends Vue {
  closeSide() {
    this.$refs.drawer.toggle(false);
  }

  openSide() {
    this.$refs.drawer.toggle(true);
  }
}
</script>

<style lang="stylus">
.content-wrap
  @apply flex
</style>
