import {
  Module,
  MutationAction,
  Mutation,
  VuexModule
} from "vuex-module-decorators";
import { Function } from "@/models/response";
import axios from "@/axios";
import { functionXml, selectionType } from "@/util";

export interface CurrentFunctionDetail {
  function: Function;
  xmlRoot: Document;
  syntaxTree: Element;
  ast: Element;
}

export enum SelectionType {
  Const,
  Function,
  Variable,
  Global,
  Type
}

export interface Selection {
  type: SelectionType;
  name: string | null;
  addr: string | null;
  origin: Element | "asm";
}

@Module({ namespaced: true })
export default class BrowseStore extends VuexModule {
  public project = "";
  public binary = "";
  public functions: Function[] = [];
  public current: CurrentFunctionDetail | null = null;
  public selection: Selection | null = null;

  get normalFunctions() {
    return this.functions.filter(x => !x.thunk);
  }

  get thunkedFunctions() {
    return this.functions.filter(x => x.thunk);
  }

  @Mutation
  public select(selection: Selection | null) {
    this.selection = selection;
  }

  @Mutation
  public selectNode(elem: Element) {
    if (!this.current) return;
    const type = elem.getAttribute("color");
    if (!type) return;
    const stype = selectionType(type);
    if (stype === null) return;

    this.selection = {
      type: stype,
      name: elem.textContent,
      addr: null,
      origin: elem
    };
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

    const { root, syntaxTree, ast } = await functionXml(
      project,
      binary,
      func.addr
    );

    return {
      current: {
        function: func,
        xmlRoot: root,
        ast,
        syntaxTree,
        selectedNode: null
      }
    };
  }
}
