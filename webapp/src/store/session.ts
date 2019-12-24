import { Module, VuexModule, MutationAction } from "vuex-module-decorators";
import { UserInfo } from "@/models/response";
import axios from "@/axios";

@Module({ namespaced: true })
export default class SessionStore extends VuexModule {
  public userInfo: UserInfo | null = null;

  get authenticated() {
    return this.userInfo != null;
  }

  @MutationAction({ mutate: ["userInfo"] })
  async checkAuthenticated() {
    try {
      const { data } = await axios.get<UserInfo>("/users/info");
      return { userInfo: data };
    } catch (e) {
      return { userInfo: null };
    }
  }
}
