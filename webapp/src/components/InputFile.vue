<template>
  <div>
    <input
      type="file"
      ref="file"
      name="file"
      id="file"
      class="opacity-0 w-0 h-0 overflow-hidden absolute"
      @change="filesChanged"
    />
    <label for="file" class="w-full border border-2 border-blue-600 bg-blue-900 rounded p-2 flex">
      <FontAwesomeIcon icon="upload" class="h-5 w-5 mx-2" />
      <div v-if="files && files.length !== 0" class="flex flex-1">
        <div class="font-bold">{{ files[0].name }}</div>
        <div class="flex-1"/>
        <div class="italic">{{ fileSize(files[0].size) }}</div>
      </div>
      <div v-else>choose file</div>
    </label>
  </div>
</template>
<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";

@Component({
  components: { FontAwesomeIcon }
})
export default class InputFile extends Vue {
  public files: FileList|null = null;

  filesChanged() {
    this.files = this.$refs.file.files;
  }

  fileSize(sz: number) {
    const prefixes = ['b', 'kb', 'mb', 'gb']
    for (const pre of prefixes) {
      const nsz = sz/1024;
      if (nsz < 10) {
        return sz.toFixed(2) + " " + pre;
      }
      sz = nsz;
    }
    return sz;
  }
}
</script>
