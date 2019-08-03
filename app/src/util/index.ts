export function syntaxClassObj(syntax: Element) {
    const cls: { [key: string]: string } = {}
    const color = nodeColor(syntax);
    if (color) {
        cls[color] = color;
    }
    return cls;
}

export function nodeColor(syntax: Element) {
    if (!syntax.attributes) { return undefined; }
    const color = syntax.attributes.getNamedItem('color');
    if (!color || !color.value) { return undefined; }
    return color.value;
}
