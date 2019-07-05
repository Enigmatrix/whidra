<template>
  <div id="app" class="bg-gray-800 min-h-screen flex flex-col">
    <nav class="bg-gray-900 text-gray-200 px-4 py-3 shadow-md flex-none">
        <span class="text-xl font-mono">whidra</span>
    </nav>
    <router-view class="flex-1"/>
  </div>
</template>
<style lang="stylus">
@import 'assets/styles/tailwind.postcss';
</style>
