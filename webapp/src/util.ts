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
