<template>
    <div class="z-50 bottom-0 right-0 left-0 fixed flex flex-col p-2">
        <div v-for="(notif, id) in notifications" class="mt-2 text-xl text-gray-500 bg-gray-900 flex flex-col w-full shadow rounded-sm border-l-4 border-blue-500" :key="id">
            <div class="flex p-2"><span>{{notif.message}}</span> <div class="flex-1"></div>
                <span class="text-sm self-end">({{notif.currentProgress}}/{{notif.maxProgress}})</span>
                <button class="ml-2">
                    <svg class="h-8 w-8 fill-current"  viewBox="0 0 24 24">
                        <path d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z"></path>
                    </svg>
                </button>
            </div>
            <div class="m-1">
                <div class="border-b-4 border-green-500" :style="notif.taskWidthPercentage"></div>
            </div>
        </div>
    </div>
</template>

<script lang="ts">
import {Vue, Component} from 'vue-property-decorator';
import {WsMessage} from '../models';

class TaskNotification {
    public maxProgress = 0;
    public currentProgress = 0;
    public message = '';

    get taskWidthPercentage() {
        let percentage = this.currentProgress / this.maxProgress * 100.0;
        if (isNaN(percentage) || percentage < 0) {
            percentage = 0;
        } else if (percentage > 100) {
            percentage = 100;
        }
        return {
            width: `${percentage}%`,
        };
    }
}

@Component({})
export default class NotificationArea extends Vue {

    private notifications: { [id: string]: TaskNotification } = {};

    public async mounted() {
        const ws = new WebSocket('ws://localhost:8000/api/event-stream');
        ws.onmessage = (ev) => {
            console.log('msg', ev.data);
            const wsMsg = JSON.parse(ev.data) as WsMessage;
            switch (wsMsg.kind) {
                case 'progress':
                    let notif = this.notifications[wsMsg.taskId];
                    if (notif === undefined) {
                        Vue.set(this.notifications, wsMsg.taskId, new TaskNotification());
                        notif = this.notifications[wsMsg.taskId];
                    }
                    switch (wsMsg.event.kind) {
                        case 'completed':
                            Vue.set(this.notifications, wsMsg.taskId, undefined);
                            break;
                        case 'indeterminate':
                            notif.message = '...';
                            break;
                        case 'progress':
                            notif.currentProgress = wsMsg.event.current;
                            notif.maxProgress = wsMsg.event.max;
                            break;
                        case 'message':
                            notif.message = wsMsg.event.msg;
                            break;
                    }
            }
        };
        ws.onclose = (ev) => {
            console.log('close', ev);
        };
        ws.onerror = (ev) => {
            console.log('error', ev);
        };
        ws.onopen = (ev) => {
            console.log('open', ev);
        };
    }
}
</script>

<style>

</style>
