<template>
            <div class="flex-1 flex justify-center items-center px-2 py-3" v-bind:class="{'bg-gray-700': active}">
                <div>
                    <svg class="h-5 w-5" viewBox="0 0 24 24">
    <path fill="currentColor" :d="path" />
                    </svg>
                </div>
                <div class="font-bold text-sm ml-2">
                    {{name}}
                </div>
            </div>

</template>

<script lang="ts">
import {Vue, Prop, Component} from 'vue-property-decorator';

@Component({})
export default class TabHeader extends Vue {
    @Prop({}) path!: string; 
    @Prop({}) name!: string; 
    @Prop({default: false}) active!: boolean; 
}
</script>
