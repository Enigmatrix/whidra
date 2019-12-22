<template>
  <div class="home flex flex-col">
    <nav class="bg-gray-900 flex flex-1 p-2 shadow-md items-center">
      <img src="favicon.ico" class="w-8 h-8 mx-2" />
      <div class="title text-2xl">whidra</div>
      <div class="flex-1"></div>
      <button class="bg-red-700 px-4 py-1 shadow rounded text-gray-100">
        <div>
          <FontAwesomeIcon icon="user-secret" />
          ADMIN
        </div>
      </button>
    </nav>

    <div class=" mx-4 mt-4 p-2 rounded">
      <div class="text-2xl flex items-center mb-2 text-blue-500">
        <FontAwesomeIcon icon="project-diagram" class="h-4 w-4 mr-2" />
        <div>google-ctf-2019</div>
      </div>
      <div class="px-4">
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          babypwn1
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          house-of-spirit
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          ropa
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          fengshui
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          realworld
        </a>
      </div>
    </div>

    <div class="mx-4 p-2 rounded">
      <div class="text-2xl flex items-center mb-2 text-blue-500">
        <FontAwesomeIcon icon="project-diagram" class="h-4 w-4 mr-2" />
        <div>project1</div>
      </div>
      <div class="px-4">
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          file1
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          file1
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          file1
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          file1
        </a>
        <a class="text-xl flex items-center text-blue-200" href=".">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          file1
        </a>
      </div>
    </div>
  </div>
</template>

<script>
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
//import HelloWorld from "@/components/HelloWorld.vue";

export default {
  components: {
    FontAwesomeIcon
  }
};
</script>
