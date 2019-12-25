<template>
  <nav class="bg-gray-900 flex p-2 shadow-md items-center">
    <button class="h-8 w-8" @click="$emit('menu-click')">
      <FontAwesomeIcon icon="bars" class="h-8 w-8 fa-w-20"></FontAwesomeIcon>
    </button>
    <img src="/favicon.ico" class="w-6 h-6 mx-2" />
    <div class="title text-2xl">whidra</div>
    <div class="flex-1"></div>
    <slot />
  </nav>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";

@Component({
  components: { FontAwesomeIcon }
})
export default class NavBar extends Vue {}
</script>
