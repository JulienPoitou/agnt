const system={label:"System",font:{variable:"font-system"}} as const;
export const fontRegistry={system,geist:system,inter:system} as const;
export type FontKey=keyof typeof fontRegistry; export const fontKeys=Object.keys(fontRegistry) as FontKey[]; export const fontVars="font-system"; export const fontOptions=fontKeys.map(key=>({key,label:fontRegistry[key].label}));
