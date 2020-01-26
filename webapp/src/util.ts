import {SelectionType} from "@/store/browse";
import axios from "@/axios";

export function genRandomId(length: number) {
  let result = "";
  const characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

export const SESS_ID = genRandomId(32);

export function syntaxClassObj(syntax: Element | undefined) {
  if (!syntax) {
    return undefined;
  }
  const cls: { [key: string]: string } = {};
  const color = nodeColor(syntax);
  if (color) {
    cls[color] = color;
  }
  return cls;
}

export function nodeColor(syntax: Element) {
  if (!syntax.attributes) {
    return undefined;
  }
  const color = syntax.attributes.getNamedItem("color");
  if (!color || !color.value) {
    return undefined;
  }
  return color.value;
}


export function selectionType(type: string): SelectionType | null {
  switch (type) {
    case "var":
      return SelectionType.Variable;
    case "const":
      return SelectionType.Const;
    case "type":
      return SelectionType.Type;
    case "global":
      return SelectionType.Global;
    case "funcname":
      return SelectionType.Function;
    default:
      return null;
  }
}

export function selectionToClassObj(type: SelectionType): any {
  switch (type) {
    case SelectionType.Variable:
      return { var: true };
    case SelectionType.Const:
      return { const: true };
    case SelectionType.Type:
      return { type: true };
    case SelectionType.Global:
      return { type: true };
    case SelectionType.Function:
      return { funcname: true };
    default:
      return null;
  }
}

export async function functionXml(
  project: string,
  binary: string,
  addr: string | undefined,
  name: string | undefined = undefined
) {
  const code = await axios
    .get<string>(`/${project}/binary/${binary}/code`, {
      params: { addr, fnName: name }
    })
    .then(x => x.data);

  const parser = new DOMParser();
  const root = parser.parseFromString(code, "text/xml");
  const syntaxTree = root.firstChild && root.firstChild.lastChild;
  const ast = root.querySelector("ast");
  return { root, syntaxTree, ast };
}
