<template>
  <div v-show="isActive">
    <slot/>
  </div>
</template>
<script lang="ts">
import { Vue, Component, Prop } from 'vue-property-decorator';

@Component({
    methods: {
        setActive(active: boolean) {
            (this as any).isActive = active;
        },
    },
})
export default class Tab extends Vue {

    @Prop({ required: true })
    public title!: string;

    @Prop({ required: true })
    public icon!: string;

    @Prop({ default: false })
    public active!: boolean;

    private isActive = this.active;
}
</script>
