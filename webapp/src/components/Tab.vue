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
                (<any>this).isActive = active;
            }
        }
    })
    export default class Tab extends Vue {

        @Prop({ required: true })
        public title!: String;

        @Prop({ required: true })
        public icon!: String;

        @Prop({ default: false })
        public active!: boolean;

        private isActive = this.active;  
    }
</script>
