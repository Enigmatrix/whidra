<template>
  <div class="flex flex-col">

    <div class=" mx-4 mt-4 p-2 rounded" v-for="proj in projects" :key="proj.name">
      <div class="text-2xl flex items-center mb-2 text-blue-500">
        <FontAwesomeIcon icon="project-diagram" class="h-4 w-4 mr-2" />
        <div>{{proj.name}}</div>
      </div>
      <div class="px-4">
        <a class="text-xl flex items-center text-blue-200" v-for="binary in proj.binaries" :key="binary.name" :href="`/browse/${proj.name}/${binary.name}`">
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          {{binary.name}}
        </a>
      </div>
    </div>

  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { Project } from "@/models/response";
import axios from "@/axios";

@Component({
  components: { FontAwesomeIcon }
})
export default class Home extends Vue {
  public projects: Project[]|null = null;

  async mounted() {
    this.projects = await axios.get<Project[]>("/projects/all").then(x => x.data);
  }
}
</script>
