import { Module, MutationAction, VuexModule } from "vuex-module-decorators";
import { Function } from "@/models/response";
import axios from "@/axios";

export interface CurrentFunctionDetail {
  function: Function;
  syntaxTree: Document;
  selectedNode: Element | null;
}

@Module({ namespaced: true })
export default class BrowseStore extends VuexModule {
  public project = "";
  public binary = "";
  public functions: Function[] = [];
  public current: CurrentFunctionDetail | null = null;

  get normalFunctions() {
    return this.functions.filter(x => !x.thunk);
  }

  get thunkedFunctions() {
    return this.functions.filter(x => x.thunk);
  }

  @MutationAction({ mutate: ["functions", "project", "binary"] })
  public async load({ project, binary }: { project: string; binary: string }) {
    const functions = await axios
      .get<Function[]>(`/${project}/binary/${binary}/functions`)
      .then(x => x.data);
    return { functions, project, binary };
  }

  @MutationAction({ mutate: ["current"] })
  public async selectFunction(func: Function) {
    const { project, binary } = this.state as BrowseStore;
    const code = await axios
      .get<string>(`/${project}/binary/${binary}/code`, {
        params: { addr: func.addr }
      })
      .then(x => x.data);

    const parser = new DOMParser();
    const root = parser.parseFromString(code, "text/xml");
    const syntaxTree = (root.firstChild &&
      root.firstChild.lastChild) as Document | null;

    return { current: { function: func, syntaxTree, selectedNode: null } };
  }
}
