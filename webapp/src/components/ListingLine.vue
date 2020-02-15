<template>
  <tr>
    <td class="pl-1 address">{{ asm.addr }}</td>

    <td v-if="asm.kind === 'data'" colspan="2">
      <p class="inline pr-2 data_value">{{ asm.value }}</p>
      <p class="inline data_type">({{ asm.type }})</p>
    </td>

    <template v-else>
      <td class="pr-2 mnemonic ">{{ lower(asm.mnemonic) }}</td>
      <td>
        <pre
          v-for="(oper, index) in asm.operands"
          :key="index"
          class="inline-flex operand"
        >
              <p v-for="(op, i) in oper" :key="i" :class="{[op.type]: true}">{{op.value}}</p>
              <p v-if="index+1 < asm.operands.length">,&nbsp;</p>
            </pre>
      </td>
    </template>

    <!--<td></td>-->
  </tr>
</template>
<script lang="ts">
  import {Component, Prop, Vue} from "vue-property-decorator";

@Component
export default class ListingLine extends Vue {
  @Prop({ required: true })
  public asm: any;

  public lower(str: string) {
    if(!str) { return str; }
    return str.toLowerCase();
  }
}
</script>
