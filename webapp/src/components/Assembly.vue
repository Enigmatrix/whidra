<template>
    <div>
        <button @click="load">load</button>
        <table class="font-code">
            <tr v-for="instr in instructions">
                <td class="bg-gray-900 px-1">{{'0x'+instr.addr.toString(16)}}</td>
                <td class="px-2">{{instr.line}}</td>
            </tr>
        </table>
    </div>
</template>

<script lang="ts">
    import {Component, Prop, Vue} from 'vue-property-decorator';
    import {Asm} from "@/models";
    import axios from "@/axios";
    import {namespace} from "vuex-class";

    const MainStore = namespace("Main");

    @Component
    export default class Assembly extends Vue {
        @Prop()
        public initialMinAddr: number | undefined;

        @Prop({required: true})
        public length!: number;

        @MainStore.State
        private binary!: string;
        @MainStore.State
        private project!: string;

        private minAddr: number = 0;
        private maxAddr: number = 0;

        private instructions: Asm[] = [];

        async load(){
            const resp = await axios.get<Asm[]>("/binary/asm", {
                params: {
                    repository: this.project,
                    binary: this.binary,
                    addr: this.minAddr,
                    length: this.length
                }
            });
            this.instructions = resp.data;
        }

        async mounted(){
            this.minAddr = this.initialMinAddr || 0;
            this.maxAddr = this.minAddr + this.length

        }
    }
</script>

<style>

</style>
