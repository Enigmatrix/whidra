<template>
    <div class="asm m-1 rounded shadow overflow-auto">
        <table class="font-code">
            <tr v-for="instr in instructions">
                <td class="bg-gray-900 shadow px-1 text-gray-600">{{'0x'+instr.addr.toString(16)}}</td>
                <td class="px-2 inline-flex">
                    <p class="mnemonic">{{instr.mnemonic}}</p>
                    &nbsp;
                    <pre v-for="(oper, index) in instr.operands" class="operand inline-flex font-code">
                        <p v-for="op in oper" :class="{[op.type]: true}">{{op.value}}</p>
                        <p v-if="index+1 < instr.operands.length">,&nbsp;</p>
                    </pre>
                </td>
            </tr>
        </table>
    </div>
</template>

<script lang="ts">
    import {Component, Prop, Vue, Watch} from "vue-property-decorator";
    import {Asm, Instruction} from "@/models";
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

        private instructions: Instruction[] = [];

        @Watch('initialMinAddr')
        async load(){
            this.minAddr = this.initialMinAddr || 0;
            const resp = await axios.get<Instruction[]>("/binary/asm", {
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

<style lang="stylus">
.asm
    background #1E1E1E
    color #D4D4D4

.mnemonic
    color #569cd6;
    font-weight bold;
.Register
    color #ce9178
.Variable
    color #9cdcfe
.Label
    color #4EC9B0
.Scalar
    color #b5cea8;

.operand > p
    display inline
</style>
