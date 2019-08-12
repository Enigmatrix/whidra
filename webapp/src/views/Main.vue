<template>
    <Slideout menu="#menu" panel="#panel">
      <nav id="menu">
        <div>Menu</div>
      </nav>
      <main id="panel">
    <Tabs>
        <Tab title="INFO" icon="M11,9H13V7H11M12,20C7.59,20 4,16.41 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,16.41 16.41,20 12,20M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,17H13V11H11V17Z">

        </Tab>
        <Tab title="CODE" active="true" icon="M14.6,16.6L19.2,12L14.6,7.4L16,6L22,12L16,18L14.6,16.6M9.4,16.6L4.8,12L9.4,7.4L8,6L2,12L8,18L9.4,16.6Z">
            <section style="height:100vh;width:100vw">sry wtf</section>
        </Tab>
        <Tab title="ASM" icon="M13,3V9H21V3M13,21H21V11H13M3,21H11V15H3M3,13H11V3H3V13Z">

        </Tab>
    </Tabs>
      </main>
    </Slideout>
</template>
<script lang="ts">
    import { Vue, Component, Prop } from 'vue-property-decorator';
    import Tabs from '@/components/Tabs.vue';
    import Tab from '@/components/Tab.vue';
    import Slideout from 'vue-slideout';

    @Component({
        components: {Tabs, Tab, Slideout}
    })
    export default class Main extends Vue {
        @Prop({})
        public project!: string;
        @Prop({})
        public binary!: string;

    }
</script>
<style>
    
  .slideout-menu {
    position: fixed;
    top: 0;
    bottom: 0;
    width: 256px;
    height: 100vh;
    overflow-y: scroll;
    -webkit-overflow-scrolling: touch;
    z-index: 0;
    display: none;
    background-color: #1D1F20;
    color: white;
  }

  .slideout-menu-left {
    left: 0;
  }

  .slideout-menu-right {
    right: 0;
  }

  
  .slideout-panel {
    position: relative;
    z-index: 1;
    will-change: transform;
    min-height: 100vh;
  }

  .slideout-open,
  .slideout-open body,
  .slideout-open .slideout-panel {
    overflow: hidden;
  }

  .slideout-open .slideout-menu {
    display: block;
  }
</style>