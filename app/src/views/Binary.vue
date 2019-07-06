<template>
    <div class="h-screen flex flex-col">
        <Navbar :custom="true">
    <div class="flex-1 flex flex-row overflow-x-auto">
            <TabHeader name="INFO" path="M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z" :active="activeTab === 'info'" @click.native="activeTab = 'info'"/>
            <TabHeader name="CODE" path="M14.6,16.6L19.2,12L14.6,7.4L16,6L22,12L16,18L14.6,16.6M9.4,16.6L4.8,12L9.4,7.4L8,6L2,12L8,18L9.4,16.6Z" :active="activeTab === 'code'" @click.native="activeTab = 'code'"/>
            <TabHeader name="ASSEMBLY" path="M13,3V9H21V3M13,21H21V11H13M3,21H11V15H3M3,13H11V3H3V13Z" :active="activeTab === 'assembly'" @click.native="activeTab = 'assembly'"/>
    </div>
        </Navbar>
    </div>	
</template>
<script lang="ts">
import {Component, Vue, Prop} from 'vue-property-decorator';
import Navbar from '../components/Navbar.vue';
import TabHeader from '../components/TabHeader.vue';

// TODO project propertu seems to have an extra slash
@Component({
    components: {
        Navbar,
        TabHeader
    }
})
export default class Binary extends Vue {
  @Prop() binary!: string;
  @Prop() project!: string;
  activeTab = 'code';
  changeTab({srcElement}) {
	console.dir(arguments);
  }
}
</script>

