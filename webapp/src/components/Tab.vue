<template>
    <div v-show="active">
        <slot/>
    </div>
</template>
<script lang="ts">
    import { Vue, Component, Prop } from 'vue-property-decorator';

    @Component({})
    export default class Tab extends Vue {

        @Prop({ required: true })
        public title!: String;

        @Prop({ required: true })
        public icon!: String;

        @Prop({ default: false })
        public active!: boolean;
    }
</script>
