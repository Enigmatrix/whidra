<template>
  <div class="home items-center flex flex-col justify-center">
      <div class="text-center">
          <form class="bg-gray-900 shadow-lg rounded text-md text-white" style="display:grid">
              <input class="mx-6 mt-6 p-2 bg-gray-700 rounded-sm" name="username" placeholder="Username"/>
              <input class="mx-6 mt-6 p-2 bg-gray-700 rounded-sm" name="password" type="password" placeholder="Password"/>
              <button type="submit" class="m-6 p-2 bg-transparent border-blue-500 border rounded border-2 text-blue-500">SUBMIT</button>
          </form>
        </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
//import HelloWorld from '@/components/HelloWorld.vue'; // @ is an alias to /src

@Component({
  components: {
  },
})
export default class Home extends Vue {}
</script>
