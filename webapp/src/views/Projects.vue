<template>
    <div class="flex flex-col">
        <nav class="h-16 bg-gray-900 shadow-md flex items-center">
            <div class="text-gray-300 ml-4 text-2xl">whidra - Projects</div>
            <div class="flex-1"></div>
            <button class="bg-blue-700 p-2 mr-4 font-bold rounded" @click="newProjectOpen()">+ PROJECT</button>
        </nav>
        <div class="flex-1 mt-4">
            <div class="m-2 rounded bg-gray-600 text-gray-900 shadow-md p-2" v-for="proj in projects" :key="proj.name">
                <div class="flex items-center">
                    <svg class="h-8 w-8 pt-1 fill-current">
                        <path d="M16,15H9V13H16M19,11H9V9H19M19,7H9V5H19M21,1H7C5.89,1 5,1.89 5,3V17C5,18.11 5.9,19 7,19H21C22.11,19 23,18.11 23,17V3C23,1.89 22.1,1 21,1M3,5V21H19V23H3A2,2 0 0,1 1,21V5H3Z"></path>
                    </svg>
                    <span class="text-2xl">{{proj.name}}</span>
                    <div class="flex-1"></div>
                    <button @click="importBinary(proj.name)">+ BINARY</button>
                </div>
                <div class="ml-4 mt-2">
                    <div class="mt-1 font-code flex items-center" v-for="bin in proj.binaries" :key="bin.name">
                        <svg class="h-6 w-6 mr-1 fill-current">
                            <path d="M14,2H6A2,2 0 0,0 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2M15.8,20H14L12,16.6L10,20H8.2L11.1,15.5L8.2,11H10L12,14.4L14,11H15.8L12.9,15.5L15.8,20M13,9V3.5L18.5,9H13Z"></path>
                        </svg>
                        <router-link :to="`/${proj.name}/${bin.name}`">{{bin.name}}</router-link>
                    </div>
                </div>
            </div>
        </div>
        <Modal ref="newProjectModal" title="NEW PROJECT" @submit="newProjectSubmit">
            <input required class="bg-gray-700 my-2 font-code text-xl appearance-none p-2" placeholder="NAME" name="name">
            <button type="submit" class="bg-blue-500 rounded p-2 mt-2 font-bold">SUBMIT</button>
        </Modal>
        <Modal ref="importBinaryModal" title="IMPORT BINARY" @submit="importBinarySubmit">
            <select name="repository" class="bg-gray-800 text-xl p-2">
                <option :value="proj.name" v-for="proj in projects" :selected="proj.name === selectedProjName">{{proj.name}}</option>
            </select>
            <input type="file" name="binary" class="">
            <button type="submit" class="bg-blue-500 rounded p-2 mt-2 font-bold">SUBMIT</button>
        </Modal>
    </div>
</template>

<script lang="ts">
import {Component, Vue} from 'vue-property-decorator';
import {Repository, WsMessage} from '@/models';
import axios from '@/axios';
import Modal from '@/components/Modal.vue';

@Component({
    components: { Modal },
})
export default class Projects extends Vue {

    public $refs!: {
        newProjectModal: any;
        importBinaryModal: any;
    };

    private projects: Repository[] = [];
    private selectedProjName: string|null = null;

    public async mounted() {
        this.projects = await axios.get<Repository[]>('/repository').then((x) => x.data);
    }

    public newProjectOpen() {
        this.$refs.newProjectModal.open();
    }

    public async newProjectSubmit(data: FormData) {
        await axios.post('/repository/new', data);
        const name = data.get('name')! as string;
        this.projects.push({ name, binaries: []});
    }

    public importBinary(projName: string) {
        this.selectedProjName = projName;
        this.$refs.importBinaryModal.open();
    }

    public async importBinarySubmit(data: FormData) {
        await axios.post('/repository/import', data);
        const repository = data.get('repository')! as string;
        const binary = data.get('binary')! as File;
        const project = this.projects.find((x) => x.name === repository);
        if (project) {
            project.binaries.push({name: binary.name});
        }
    }
}
</script>
