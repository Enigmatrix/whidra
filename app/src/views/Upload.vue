<template>
    <form :action="`/api/upload/${project}`" method="post" class="flex flex-col p-4 min-h-screen"  enctype="multipart/form-data">
        <div class="text-3xl">Upload to <b>{{project}}</b></div>
        <input type="file" name="binary" accept="*" class="m-2" />
        <div class="flex-1"/>
        <button type="submit" class="border border-2 border-blue-500 text-blue-500 m-2 p-2">UPLOAD</button>
    </form>
</template>
<script lang="ts">
import {Component, Prop, Vue} from "vue-property-decorator";

@Component({})
export default class Upload extends Vue {
    @Prop({}) project!: string;
}
</script>

