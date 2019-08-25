<template>
  <div id="app" class="min-h-screen bg-gray-800 text-gray-300">
    <router-view/>
    <NotificationArea/>
  </div>
</template>
<style lang="stylus">
.bg-smoke-light
  background: rgba(0,0,0,0.4)

#app
  font-family 'Blinker', Helvetica, Arial, sans-serif

.font-code
  font-family 'Iosevka Nerd Font', Inconsolata

@import url('https://fonts.googleapis.com/css?family=Blinker|Fira+Code&display=swap');

@font-face
  font-family "Iosevka Nerd Font"
  src: url('/Iosevka Nerd Font Complete.ttf');
</style>
<script lang="ts">
import NotificationArea from '@/components/NotificationArea.vue';

export default {
  components: { NotificationArea },
}
</script>
