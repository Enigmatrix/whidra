<template>
  <div class="flex flex-col flex-1">
    <nav class="bg-gray-900 flex p-2 shadow-md items-center">
      <img src="favicon.ico" class="w-8 h-8 mx-2" />
      <div class="title text-2xl">whidra</div>
      <div class="flex-1"></div>
    </nav>

    <div class="flex flex-col flex-1">
      <form class="m-auto rounded shadow bg-blue-800 p-4 font-bold">
        <input
          class="block p-2 bg-blue-900 my-4 rounded border border-2 border-blue-600"
          placeholder="username"
        />
        <input
          type="password"
          class="block p-2 bg-blue-900 my-4 rounded border border-2 border-blue-600"
          placeholder="password"
        />
        <button
          class="float-right p-2 m-2 bg-green-600 text-white rounded shadow"
        >
          LOGIN
        </button>
      </form>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import axios from "@/axios";

@Component
export default class Login extends Vue {}
</script>
