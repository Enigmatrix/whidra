<template>
    <div class="bg-gray-800 min-h-screen">
        <nav class="h-10 bg-gray-900 flex text-lg fixed top-0 right-0 left-0">
            <div class="w-10">
            </div>
            <div v-for="tab in tabs" @click="setActive(tab)" class="flex-1 text-center flex" :class="{'bg-gray-800': tab.title === activeTab.title}">
                <div class="m-auto flex items-center">
                    <svg class="h-4 w-4 mr-1 fill-current" viewBox="0 0 24 24">
                        <path :d="tab.icon"></path>
                    </svg>
                    <span class="text-sm">{{tab.title}}</span>
                </div>
            </div>
        </nav>
        <slot/>
    </div>
</template>
<script lang="ts">
import { Vue, Component } from 'vue-property-decorator';

export interface TabProp {
    title: string;
    icon: string;
    setActive: (b: boolean) => void;
}

@Component({})
export default class Tabs extends Vue {
    private tabs: TabProp[] = [];
    private activeTab: TabProp|null = null;

    public setActive(tab: TabProp) {
        if (this.activeTab) {
            this.activeTab.setActive(false);
        }
        tab.setActive(true);
        this.activeTab = tab;
    }

    public mounted() {
        for (const tab of this.$slots.default!) {
            const props = tab.componentInstance!.$props;
            const tabProps = {
                title: props.title,
                icon: props.icon,
                setActive: (t: boolean) => (tab.componentInstance! as any).setActive(t),
            };
            if (props.active) {
                this.activeTab = tabProps;
            }
            this.tabs.push(tabProps);
        }
    }
}
</script>
