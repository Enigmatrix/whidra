<template>
  <div id="app" class="bg-gray-800 text-gray-300">
    <router-view />
    <NotificationArea />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import NavBar from "@/components/NavBar.vue";
import NotificationArea from "@/components/NotificationArea.vue";

@Component({
  components: { NotificationArea, NavBar }
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
