<template>
    <div class="flex flex-col text-gray-200 my-4">
        <div class="flex" @click="chevronClick">
            <span class="mx-2">
                <svg class="h-8 w-8" viewBox="0 0 24 24" v-if="expanded">
                    <path fill="currentColor" d="M7.41,8.58L12,13.17L16.59,8.58L18,10L12,16L6,10L7.41,8.58Z" />
                </svg>
                <svg class="h-8 w-8" viewBox="0 0 24 24" v-else>
                    <path fill="currentColor" d="M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z" />
                </svg>
            </span>
            <span class="text-xl">{{name}}</span>
        </div>
        <div v-if="expanded">
            <div v-for="binary in binaries" :key="binary" class="ml-12 my-2 flex align-center">
                <span>
                    <svg class="h-6 w-6" viewBox="0 0 24 24">
                        <path fill="currentColor" d="M13,9V3.5L18.5,9M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6Z" />
                    </svg>
                </span>
                <span class="mx-2">{{binary}}</span>
            </div>
        </div>
    </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from 'vue-property-decorator';

@Component
export default class Project extends Vue {
    @Prop() private name!: string;

    expanded = false
    binaries: any[]|null = null

    chevronClick(){
        if(!this.expanded && this.binaries === null){
            //TODO get binaries from api
            //TODO get a upload button?
            this.binaries = ['archimedes']
        }
        this.expanded = !this.expanded;
    }
}
</script>

