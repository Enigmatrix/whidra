<template>
  <div id="app" class="bg-gray-800 text-gray-300 min-h-screen flex flex-col">
    <router-view />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import NavBar from "@/components/NavBar.vue";

@Component({
  components: { NavBar }
})
export default class App extends Vue {}
</script>

<style lang="stylus">
#app
  font-family 'PT Sans','Avenir', Helvetica, Arial, sans-serif
  -webkit-font-smoothing antialiased
  -moz-osx-font-smoothing grayscale

@import url('https://fonts.googleapis.com/css?family=PT+Sans&display=swap');
</style>
