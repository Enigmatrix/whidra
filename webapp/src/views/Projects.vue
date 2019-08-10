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
        <div class="z-50 bottom-0 right-0 left-0 fixed text-xl text-gray-500 flex flex-col bg-gray-900 m-2 p-2">
            <div class="flex"><span>{{taskMsg}}</span> <div class="flex-1"></div>
                <span>({{taskCurrent}}/{{taskMax}})</span>
                <button class="ml-2">
                    <svg class="h-8 w-8 fill-current"  viewBox="0 0 24 24">
                        <path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z"></path>
                    </svg>
                </button>
            </div>
            <div class="border-b-2 border-green-500" :style="taskWidthPercentage"></div>
        </div>
    </div>
</template>

<script lang="ts">
import {Component, Vue} from 'vue-property-decorator';
import {Repository, WsMessage} from "@/models/model";
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

    private taskMsg = "";
    private taskCurrent = 0;
    private taskMax = 0;

    get taskWidthPercentage() {
        const o = {
            'width': Math.min(this.taskCurrent/this.taskMax*100, 100)+'%'
        };
        console.dir(o);
        return o;
    }

    public async mounted() {
        this.projects = await axios.get<Repository[]>('/repository').then((x) => x.data);

        const ws = new WebSocket('ws://localhost:8000/api/event-stream');
        ws.onmessage = (ev) => {
            console.log("msg", ev.data);
            const wsMsg = JSON.parse(ev.data) as WsMessage;
            switch (wsMsg.kind) {
                case 'progress':
                    switch (wsMsg.event.kind) {
                        case 'completed':
                            this.taskMsg = 'COMPLETED!';
                            break;
                        case 'indeterminate':
                            this.taskMsg = '...';
                            break;
                        case 'progress':
                            this.taskCurrent = wsMsg.event.current;
                            this.taskMax = wsMsg.event.max;
                            break;
                        case 'message':
                            this.taskMsg = wsMsg.event.msg;
                            break;
                    }
            }
        };
        ws.onclose = (ev) => {
            console.log("close", ev);
        };
        ws.onerror = (ev) => {
            console.log("error", ev);
        };
        ws.onopen = (ev) => {
            console.log("open", ev);
        }
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

    }
}
</script>
