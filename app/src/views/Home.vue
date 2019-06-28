<template>
  <div class="home bg-gray-800 text-gray-200">
      <nav class="p-4 shadow-md">
          <h1 class="font-bold text-2xl">pwnbro</h1>
      </nav>
    <main class=" flex md:flex-col flex-row">
        <section>
            <h2>Code</h2>
        </section>
    </main>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import HelloWorld from '@/components/HelloWorld.vue'; // @ is an alias to /src

@Component({
  components: {
    HelloWorld,
  },
})
export default class Home extends Vue {}
</script>
