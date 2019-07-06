<template>
    <div class="flex flex-col min-h-screen">
        <Navbar class="flex-none"/>
  <div class="home items-center flex flex-col justify-center flex-1">
      <div class="text-center">
          <form class="bg-gray-900 shadow-lg rounded text-md" style="display:grid" method="post" action="/api/user/login">
              <input class="mx-6 mt-6 p-2 bg-gray-700 rounded-sm" name="username" placeholder="Username"/>
              <input class="mx-6 mt-6 p-2 bg-gray-700 rounded-sm" name="password" type="password" placeholder="Password"/>
              <button type="submit" class="m-6 p-2 bg-transparent border-blue-500 border rounded border-2 text-blue-500">SUBMIT</button>
          </form>
        </div>
  </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Navbar from '@/components/Navbar.vue'; // @ is an alias to /src

@Component({
  components: {
      Navbar
  },
})
export default class Home extends Vue {}
</script>
