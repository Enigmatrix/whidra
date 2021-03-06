<template>
    <div class="min-h-screen">
        <Slide>
            <div class="font-extrabold font-xl m-4">FUNCTIONS</div>
            <div @click="() => functionSelected(func)" v-for="func in functions" class="flex flex-col text-sm py-1 px-2 border-b border-green-500" :class="{'bg-green-700': currentFunction === func}">
                <div class="flex font-bold text-white">
                    <span class="text-base">{{func.name}}</span>
                    <div class="flex-1"></div>
                    <span class="font-code">{{hex(func.addr)}}</span>
                </div>
                <Prism inline language="cpp" class="text-gray-300 font-code">{{func.signature}}</Prism>
            </div>
        </Slide>
        <Tabs>
            <Tab title="INFO" icon="M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z">

            </Tab>
            <Tab title="CODE" active="true" icon="M14.6,16.6L19.2,12L14.6,7.4L16,6L22,12L16,18L14.6,16.6M9.4,16.6L4.8,12L9.4,7.4L8,6L2,12L8,18L9.4,16.6Z">
                <Code @selectnode="codeNodeSelected" :address="currentFunction.addr" v-if="currentFunction"/>
            </Tab>
            <Tab title="ASM" icon="M13,3V9H21V3M13,21H21V11H13M3,21H11V15H3M3,13H11V3H3V13Z">
                <Assembly length="50" :initialMinAddr="currentFunction.addr" v-if="currentFunction"></Assembly>
            </Tab>
            <Tab title="TERM" icon="M20,19V7H4V19H20M20,3A2,2 0 0,1 22,5V19A2,2 0 0,1 20,21H4A2,2 0 0,1 2,19V5C2,3.89 2.9,3 4,3H20M13,17V15H18V17H13M9.58,13L5.57,9H8.4L11.7,12.3C12.09,12.69 12.09,13.33 11.7,13.72L8.42,17H5.59L9.58,13Z">

            </Tab>
        </Tabs>
        <Info></Info>
    </div>


</template>
<script lang="ts">
import { Vue, Component, Prop } from 'vue-property-decorator';
import Tabs from '@/components/Tabs.vue';
import Tab from '@/components/Tab.vue';
// @ts-ignore
import { Slide } from 'vue-burger-menu';
// @ts-ignore
import Prism from 'vue-prism-component';
import {namespace} from "vuex-class";
import {Func} from '@/models';
import 'prismjs';
import 'prismjs/components/prism-c';
import 'prismjs/components/prism-cpp';
import 'prismjs/themes/prism-okaidia.css';
import Code from '@/components/Code.vue';
import {FuncSelection} from '@/store/main';
import Info from '@/components/Info.vue';
import Assembly from '@/components/Assembly.vue';

const MainStore = namespace('Main');

@Component({
    components: {Assembly, Info, Code, Tabs, Tab, Slide, Prism},
})
export default class Main extends Vue {
    @Prop({})
    public project!: string;

    @Prop({})
    public binary!: string;

    @MainStore.State
    private functions!: Func[];

    @MainStore.State
    private currentFunction!: Func | undefined;

    @MainStore.Mutation
    private setProject!: (s: string) => void;

    @MainStore.Mutation
    private setBinary!: (s: string) => void;

    @MainStore.Action
    private getFunctions!: () => Promise<void>;

    @MainStore.Mutation
    private selectFunction!: (func: Func) => Promise<void>;

    @MainStore.Mutation
    private selectNode!: (e: Element) => void;

    async mounted() {
        this.setBinary(this.binary);
        this.setProject(this.project);

        await this.getFunctions();
    }

    async functionSelected(func: Func) {
        await this.selectFunction(func);
    }

    hex(addr: Number){
        return "0x"+addr.toString(16);
    }

    codeNodeSelected(elem: Element) {
        this.selectNode(elem);
    }
}
</script>
<style>
    #app .bm-burger-button {
        position: fixed;
        width: 1.125rem;
        height: 1.125rem;
        left: 0.750rem;
        top: 0.750rem;
        cursor: pointer;
        z-index: 10;
    }

    #app .bm-burger-bars {
        background-color: white;
    }

    #app .bm-menu {
        padding: 0;
    }

    #app .bm-item-list {
        margin: 0;
    }

    #app .bm-item-list > * {
        margin: 0;
    }

    :not(pre) > code[class*="language-"], pre[class*="language-"] {
        background: transparent;
        font-family: "Iosevka Nerd Font", monospace
    }
</style>

