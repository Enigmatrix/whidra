<template>
  <span
    v-if="syntax.childNodes && syntax.childNodes.length !== 0"
    :class="classObj"
  >
    <SyntaxNode
      v-for="syn in syntax.childNodes"
      :syntax="syn"
      :key="syn.xpath"
    />
  </span>
  <pre v-else-if="syntax.nodeType === 3" :class="classObj" @click="select">{{
    syntax.nodeValue
  }}</pre>
  <pre v-else-if="syntax.nodeName === 'break'">
&#10;{{ "  ".repeat(+syntax.attributes.indent.value) }}</pre
  >
</template>

<script lang="ts">
import { Vue, Prop, Component } from "vue-property-decorator";
import { syntaxClassObj } from "@/util";

@Component({ name: "SyntaxNode" })
export default class SyntaxNode extends Vue {
  @Prop({ required: true })
  public syntax!: Element;

  get classObj() {
    return syntaxClassObj(this.syntax);
  }

  get obj() {
    return new XMLSerializer().serializeToString(this.syntax);
  }

  public select() {
    // TODO
  }
}
</script>
