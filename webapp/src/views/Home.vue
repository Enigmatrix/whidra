<template>
  <Page>
    <div slot="nav">
      <button
        class="flex items-center text-white p-2 bg-green-700 shadow rounded"
        @click="addProjectOpen"
      >
        <FontAwesomeIcon icon="plus" class="h-5 w-5 mx-2" />
        <div class="mr-1">PROJECT</div>
      </button>
    </div>

    <div class="ml-4 mt-4 p-2 rounded" v-for="proj in projects" :key="proj.name">
      <div class="text-2xl flex items-center mb-2 text-blue-500">
        <FontAwesomeIcon icon="project-diagram" class="h-4 w-4 mr-2" />
        <div>{{proj.name}}</div>
        <div class="flex-1"></div>
        <button @click="uploadBinaryOpen(proj.name)">
          <FontAwesomeIcon icon="upload" class="h-5 w-5 mx-2" />
        </button>
      </div>
      <div class="px-4">
        <a
          class="text-xl flex items-center text-blue-200"
          v-for="binary in proj.binaries"
          :key="binary.name"
          :href="`/browse/${proj.name}/${binary.name}`"
        >
          <FontAwesomeIcon icon="file-code" class="h-4 w-4 mx-2" />
          {{binary.name}}
        </a>
      </div>
    </div>

    <modal name="add-project" classes="bg-blue-900 shadow" adaptive height="auto">
      <form class="flex flex-col w-full p-4">
        <input
          class="block p-2 bg-blue-900 my-4 rounded border border-2 border-blue-600 w-full"
          placeholder="project name"
        />

        <button
          class="p-2 border self-end border-2 border-white text-white rounded shadow px-4"
        >CREATE</button>
      </form>
    </modal>

    <modal name="upload-binary" classes="bg-blue-900 shadow" adaptive height="auto">
      <form class="flex flex-col w-full p-4 py-6">
        <select class="block p-2 bg-blue-900 rounded border border-2 border-blue-600 w-full">
          <option
            v-for="proj in projects"
            :key="proj.name"
            :selected="proj.name === selectedProject"
          >
            <div>{{proj.name}}</div>
          </option>
        </select>

        <input
          class="block p-2 bg-blue-900 my-4 rounded border border-2 border-blue-600 w-full"
          placeholder="name"
          name="name"
        />

        <div class="w-full flex">
          <input
            type="file"
            name="file"
            id="file"
            class="opacity-0 w-0 h-0 overflow-hidden absolute"
          />
          <label for="file" class="w-full border border-2 border-blue-600 bg-blue-900 rounded p-2">
            <FontAwesomeIcon icon="upload" class="h-5 w-5 mx-2" />
            {{uploadStatus}}
          </label>
        </div>

        <button
          class="p-2 border border-2 border-white text-white rounded shadow px-4 float-right mt-4 self-end"
        >UPLOAD</button>
      </form>
    </modal>
  </Page>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { Project } from "@/models/response";
import Page from "@/components/Page.vue";
import axios from "@/axios";

@Component({
  components: { FontAwesomeIcon, Page }
})
export default class Home extends Vue {
  public projects: Project[] | null = null;
  public selectedProject: string | null = null;
  public uploadStatus = "choose file";

  async mounted() {
    this.projects = await axios
      .get<Project[]>("/projects/all")
      .then(x => x.data);
  }

  addProjectOpen() {
    this.$modal.show("add-project");
  }

  uploadBinaryOpen(proj: string) {
    this.selectedProject = proj;
    this.$modal.show("upload-binary");
  }
}
</script>
