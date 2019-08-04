<template>
    <div class="fixed inset-0 z-50 overflow-auto bg-smoke-light flex" v-if="show" @click.self="show=false">
        <div class="relative bg-gray-800 w-full my-auto mx-4 shadow-md flex-col flex p-4 rounded">
            <div><span class="font-bold text-3xl">{{title}}</span></div>
            <form ref="form" class="flex flex-col pt-4 " @submit.prevent="submit">
                <slot></slot>
            </form>
        </div>
    </div>
</template>
<script lang="ts">
import {Component, Prop, Vue} from 'vue-property-decorator';

@Component({})
export default class Modal extends Vue {

    public $refs!: {
        form: HTMLFormElement;
    };

    @Prop({})
    private title!: string;

    private show = false;

    public open() {
        this.show = true;
    }
    public close() {
        this.show = false;
    }

    public submit() {
        const data = new FormData(this.$refs.form);
        this.$emit('submit', data);
        this.close();
    }
}
</script>

<style lang="stylus">
.bg-smoke-light
    background: rgba(0,0,0,0.4)
</style>
