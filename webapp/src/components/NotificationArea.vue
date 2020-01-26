<template>
  <div class="z-50 bottom-0 right-0 left-0 fixed flex flex-col p-2">
    <div
      v-for="(notif, id) in notifications"
      class="mt-2 text-xl text-gray-500 bg-gray-900 flex flex-col w-full shadow rounded-sm border-l-4 border-blue-500"
      :key="id"
    >
      <div class="flex p-2">
        <span>{{ notif.message }}</span>
        <div class="flex-1"></div>
        <span class="text-sm self-end"
          >({{ notif.currentProgress }}/{{ notif.maxProgress }})</span
        >
        <button class="ml-2" @click="removeNotif(id)">
          <svg class="h-8 w-8 fill-current" viewBox="0 0 24 24">
            <path
              d="M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z"
            />
          </svg>
        </button>
      </div>
      <div class="m-1">
        <div
          class="border-b-4 border-green-500"
          :style="notif.taskWidthPercentage"
        ></div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Notification, ProgressNotification } from "@/models/notifications";
import { WsOut } from "@/models/response";
import { Component, Vue, Watch } from "vue-property-decorator";
import { SESS_ID } from "@/util";
import { namespace } from "vuex-class";

const SessionStore = namespace("SessionStore");

@Component
export default class NotificationArea extends Vue {
  public notifications: Record<string, Notification> = {};

  get stale() {
    const notif = new ProgressNotification();
    notif.message = "hello!";
    notif.maxProgress = 100;
    notif.currentProgress = 50;
    return notif;
  }

  @SessionStore.Getter
  public authenticated!: boolean;

  public removeNotif(taskId: string) {
    Vue.set(this.notifications, taskId, undefined);
  }

  @Watch("authenticated")
  public async whenAuthenticated(auth: boolean) {
    if (auth) {
      await this.connect();
    } else {
      // await this.disconnect();
    }
  }

  public async connect() {
    const loc = window.location;
    const ws = new WebSocket(
      (loc.protocol === "https:" ? "wss" : "ws") +
        `://${loc.host}/api/event-stream/${SESS_ID}`
    );

    ws.onclose = ev => window.console.log("close", ev);
    ws.onerror = ev => window.console.log("error", ev);
    ws.onopen = ev => window.console.log("open", ev);

    ws.onmessage = async ev => {
      window.console.log("msg", ev);
      const wsMsg = JSON.parse(ev.data) as WsOut;
      let notif: Notification | undefined = undefined;
      switch (wsMsg.kind) {
        case "progress":
          notif = this.notifications[wsMsg.taskId] as
            | ProgressNotification
            | undefined;
          if (notif === undefined) {
            Vue.set(
              this.notifications,
              wsMsg.taskId,
              new ProgressNotification()
            );
            notif = this.notifications[wsMsg.taskId] as ProgressNotification;
          }
          switch (wsMsg.event.kind) {
            case "completed":
              await this.$nextTick();
              this.removeNotif(wsMsg.taskId);
              break;
            case "indeterminate":
              notif.message = "???";
              break;
            case "progress":
              notif.currentProgress = wsMsg.event.current;
              notif.maxProgress = wsMsg.event.max;
              break;
            case "message":
              if (!notif) {
                return;
              }
              notif.message = wsMsg.event.msg;
              break;
          }
          break;
      }
    };
  }
}
</script>
