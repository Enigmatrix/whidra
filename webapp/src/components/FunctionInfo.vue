<template>
    <Code :fnname="selectedNode.textContent" class="bg-gray-800 fninfo" ></Code>
</template>

<script lang="ts">
import {Component, Prop, Vue} from 'vue-property-decorator';
import {namespace} from 'vuex-class';
import Code from '@/components/Code.vue';

const MainStore = namespace("Main");

@Component({
    components: {Code}
})
export default class FunctionInfo extends Vue {

    @MainStore.State
    private selectedNode!: Element;

}
</script>

<style>

</style>
