<template>
  <nav class="bg-gray-900 flex p-2 shadow-md items-center">
    <img src="favicon.ico" class="w-8 h-8 mx-2" />
    <div class="title text-2xl">whidra</div>
    <div class="flex-1"></div>
    <div class="flex" v-if="authenticated">
      <button
        class="bg-gray-800 px-2 py-1 shadow rounded text-gray-100 flex items-center mx-2"
      >
        <FontAwesomeIcon icon="cog" class="mr-1" />
        <div>{{ userInfo.name }}</div>
      </button>
      <button class="bg-red-700 px-2 py-1 shadow rounded text-gray-100">
        <FontAwesomeIcon icon="user-secret" class="mx-1" />
      </button>
    </div>
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
export default class NavBar extends Vue {
  @SessionStore.Getter
  public authenticated!: boolean;

  @SessionStore.State
  public userInfo!: UserInfo;
}
</script>
