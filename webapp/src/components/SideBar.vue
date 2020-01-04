<template>
  <nav class="bg-blue-900 h-full min-h-screen shadow-lg">
    <div class="flex flex-col" v-if="authenticated">
      <slot>
        <div class="flex flex-col w-full">
          <div
            class="flex items-center border-b border-blue-700 w-full py-2 px-2"
          >
            <img src="/favicon.ico" class="w-6 h-6 mx-4" />
            <div class="title text-2xl font-bold">whidra</div>
          </div>

          <a class="px-2 py-2 flex items-center" href="/">
            <FontAwesomeIcon icon="home" class="mx-4 fa-w-20 h-6 w-6" />
            <div class="text-xl">Home</div>
          </a>
          <a class="px-2 py-2 flex items-center" href="/admin">
            <FontAwesomeIcon icon="user-secret" class="mx-4 fa-w-20 h-6 w-6" />
            <div class="text-xl">Admin</div>
          </a>
        </div>
      </slot>
      <div class="flex-1"></div>
      <button
        class="px-4 py-2 border-t border-blue-700 text-gray-100 flex items-center"
      >
        <FontAwesomeIcon icon="cog" class="mr-2 h-6 w-6 fa-w-20" />
        <div class="text-lg">{{ userInfo.name }}</div>
      </button>
    </div>
    <div v-else></div>
  </nav>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { State, Getter, Action, Mutation, namespace } from "vuex-class";
import { UserInfo } from "@/models/response";

const SessionStore = namespace("SessionStore");

@Component({
  components: { FontAwesomeIcon }
})
export default class SideBar extends Vue {
  @SessionStore.Getter
  public authenticated!: boolean;

  @SessionStore.State
  public userInfo!: UserInfo;
}
</script>

<style lang="stylus">
.drawer-wrap
  overflow-y auto
  overflow-x hidden
</style>
