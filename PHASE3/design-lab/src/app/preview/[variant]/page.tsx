import { notFound } from "next/navigation";

import { PreviewShell, type PreviewVariant } from "../_components/preview-shell";

const variants: PreviewVariant[] = ["linear", "forensics", "minimal"];

export default async function PreviewPage({ params }: Readonly<{ params: Promise<{ variant: string }> }>) {
  const { variant } = await params;
  if (!variants.includes(variant as PreviewVariant)) notFound();
  return <PreviewShell variant={variant as PreviewVariant} />;
}
