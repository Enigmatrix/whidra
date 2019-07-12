<template>
    <div class="min-h-screen">
        <Navbar>
            <div class="flex-1"/>
                <button class="text-blue-500 border-2 border px-2 border-blue-500 rounded" @click="newProject">NEW</button>
        </Navbar>
        <div v-for="proj in projects" :key="proj">
            <Project :name="proj"/>
        </div>


        <div class="fixed inset-0 z-50 overflow-auto bg-smoke-light flex" v-if="modal" @click.self="modal=false">
            <div class="relative bg-gray-800 w-8/12 m-auto flex-col flex p-4 rounded">
            <span class="font-bold text-2xl mb-4">NEW PROJECT</span>
            <form class="flex flex-col" v-on:submit.prevent="onSubmit">
                <input class="bg-gray-700 my-2 text p-2" name="name" v-model="newProjectName"></input>
                <button type="submit" class="bg-blue-500 rounded p-2 mt-2 font-bold">SUBMIT</button>
            </form>
            </div>
        </div>
    </div>

</template>
<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Project from '../components/Project.vue';
import Navbar from '../components/Navbar.vue';
import axios from '../axios';

@Component({
  components: {
      Project,
      Navbar
  },
})
export default class Projects extends Vue {
    projects = [];
    modal = false;
    newProjectName = '';
    async mounted(){
        await this.getProjects();
    }
    async getProjects(){
        this.projects = await axios.get<string[]>("/projects/all").then(x => x.data);
    }
    async newProject(){
        this.modal = true;
    }
    async onSubmit(){
        console.log(this.newProjectName);
        await axios.post('/projects/new', {name: this.newProjectName});
        await this.getProjects();
        this.modal = false;
    }
}
</script>

<style lang="stylus">

.bg-smoke-light
    background: rgba(0,0,0,0.4)

</style>

