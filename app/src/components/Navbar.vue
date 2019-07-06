<template>
    <nav v-if="!custom" class="bg-gray-900 text-gray-200 px-4 py-3 shadow-md flex flex-row">
        <span class="text-xl font-mono" v-if="title">whidra</span>
        <slot/>
    </nav>
    <nav v-else class="bg-gray-900 text-gray-200 shadow-md">
    <slot/>
    </nav>
</template>

<script lang="ts">
import {Prop, Vue, Component} from 'vue-property-decorator';

@Component({})
export default class Navbar extends Vue {
    @Prop({}) title!: boolean; 
    @Prop({default: false}) custom!: boolean; 
};
</script>


