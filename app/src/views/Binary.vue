<template>
    <div class="h-screen flex flex-col">
        <Navbar :custom="true">
    <div class="flex-1 flex flex-row overflow-x-auto">
        <button>
            <svg class="h-8 w-8 ml-2 mr-2" viewBox="0 0 24 24" @click="side=true">
                <path fill="currentColor" d="M3,6H21V8H3V6M3,11H21V13H3V11M3,16H21V18H3V16Z" />
            </svg>
        </button>
            <TabHeader name="INFO" path="M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z" :active="activeTab === 'info'" @click.native="activeTab = 'info'"/>
            <TabHeader name="CODE" path="M14.6,16.6L19.2,12L14.6,7.4L16,6L22,12L16,18L14.6,16.6M9.4,16.6L4.8,12L9.4,7.4L8,6L2,12L8,18L9.4,16.6Z" :active="activeTab === 'code'" @click.native="activeTab = 'code'"/>
            <TabHeader name="ASSEMBLY" path="M13,3V9H21V3M13,21H21V11H13M3,21H11V15H3M3,13H11V3H3V13Z" :active="activeTab === 'assembly'" @click.native="activeTab = 'assembly'"/>
    </div>
        </Navbar>

        <Code :syntaxes="syntax"></Code>
        
        <div class="fixed inset-0 z-50 overflow-auto bg-smoke-light flex" v-if="side" @click.self="side=false">
            <div class="absolute min-h-full left bg-gray-800 w-8/12 m-auto flex-col flex p-4 shadow-lg">
            <span class="font-bold text-2xl mb-4">FUNCTIONS</span>
            <div class="flex flex-col">
                <div v-for="fn in functions" :key="fn[1]" class="flex" @click="select(fn)">
                    <span class="font-mono text-sm">{{fn[1]}}</span>
                    <div class="flex-1"/>
                    <span class="font-sans text-sm">{{fn[0]}}</span>
                </div>
            </div>
            </div>
        </div>

        <Info/>

    </div>	
</template>
<script lang="ts">
import {Component, Vue, Prop} from 'vue-property-decorator';
import Navbar from '../components/Navbar.vue';
import TabHeader from '../components/TabHeader.vue';
import Code from '../components/Code.vue';
import Info from '../components/Info.vue';
import axios from '../axios';
import {parseString} from 'xml2js';
import { promisify } from 'util';
import {mapState, mapMutations, mapActions, mapGetters} from 'vuex';

// TODO project property seems to have an extra slash
@Component({
    components: {
        Navbar,
        TabHeader,
        Code,
        Info
    },
    computed: { ...mapState(['functions', 'selectedNode']), ...mapGetters(['syntax']) },
    methods: { ...mapMutations(['setPre',]), ...mapActions(['setFunction', 'getFunctions']) }
})
export default class Binary extends Vue {
  @Prop() binary!: string;
  @Prop() project!: string;

  side=false;
  info=true;
  activeTab = 'code';

    
  async mounted(){
      await this.setPre({ binary: this.binary, project: this.project });
      await this.getFunctions();
      this.select( this.functions.find(x => x[0] == "main") || this.functions[0]);
  }
  async select([fnName, fnAddr]: [string, string]){
      this.setFunction(fnAddr);
  }
}
</script>

