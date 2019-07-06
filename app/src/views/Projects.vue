<template>
    <div>
        <Navbar>
            <div class="flex-1"/>
                <button class="text-blue-500 border-2 border px-2 border-blue-500 rounded">NEW</button>
        </Navbar>
        <div v-for="proj in projects" :key="proj">
            <Project :name="proj"/>
        </div>
    </div>
</template>
<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import Project from '../components/Project.vue';
import Navbar from '../components/Navbar.vue';

@Component({
  components: {
      Project,
      Navbar
  },
})
export default class Projects extends Vue {
    projects = ['google-ctf-2018', 'hitb-gsec']
}
</script>

