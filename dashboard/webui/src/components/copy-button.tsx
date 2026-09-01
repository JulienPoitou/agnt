import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { copyToClipboard, cn } from "@/lib/utils";

export function CopyButton({
  value,
  className,
  size = "icon",
  label,
}: {
  value: string;
  className?: string;
  size?: "icon" | "sm";
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      size={size}
      variant="ghost"
      className={cn("text-muted-foreground hover:text-foreground", className)}
      onClick={async (e) => {
        e.stopPropagation();
        const ok = await copyToClipboard(value);
        if (ok) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        }
      }}
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {label && <span className="text-xs">{copied ? "Copied" : label}</span>}
    </Button>
  );
}
