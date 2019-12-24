<template>
  <div class="flex flex-col flex-1">
    <div class="flex flex-col flex-1">
      <form
        class="m-auto rounded shadow bg-blue-800 p-4 font-bold"
        v-on:submit.prevent="login"
      >
        <div
          class="bg-orange-600 p-2 text-white text-sm font-thin"
          v-if="error"
        >
          <FontAwesomeIcon icon="exclamation-triangle" class="h-4 w-4" />
          {{ error }}
        </div>
        <input
          class="block p-2 bg-blue-900 my-4 rounded border border-2 border-blue-600"
          placeholder="username"
          v-model="user.username"
        />
        <input
          type="password"
          class="block p-2 bg-blue-900 my-4 rounded border border-2 border-blue-600"
          placeholder="password"
          v-model="user.password"
        />
        <button
          class="float-right p-2 m-2 bg-green-600 text-white rounded shadow"
        >
          LOGIN
        </button>
      </form>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import { FontAwesomeIcon } from "@fortawesome/vue-fontawesome";
import { State, Getter, Action, Mutation, namespace } from "vuex-class";
import axios from "@/axios";

const SessionStore = namespace("SessionStore");

@Component({
  components: { FontAwesomeIcon }
})
export default class Login extends Vue {
  public $refs!: {
    form: HTMLFormElement;
  };

  public error: string | null = null;
  public user = { username: "", password: "" };

  @SessionStore.Action
  public checkAuthenticated!: () => Promise<void>;

  async login() {
    try {
      await axios.post("/users/login", null, { params: this.user });
      this.$router.push("/");
    } catch (e) {
      this.error = "Incorrect login";
    }
  }
}
</script>
