<template>
  <div id="app" class="bg-gray-800 text-white min-h-screen">
    <router-view/>
  </div>
</template>
<style lang="stylus">
@import 'assets/styles/tailwind.postcss';
</style>
<style>
@font-face {
  font-family: 'Source Code Pro Patched';
  src: local('Source Code Pro Patched'), url('/SourceCodeProPatched.ttf');
}
* {
  text-rendering: optimizeLegibility;
}
</style>
