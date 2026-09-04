import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useStartScan } from "@/api/queries";

type ActivityMode = "active" | "passive";

export default function NewScanDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const navigate = useNavigate();
  const [targets, setTargets] = useState("");
  const [scanMode, setScanMode] = useState("single");
  const [reconMode, setReconMode] = useState<ActivityMode>("active");
  const [scanIntensity, setScanIntensity] = useState<ActivityMode>("active");
  const [instruction, setInstruction] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const mutation = useStartScan();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const list = targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (list.length === 0) {
      setError("Provide at least one target.");
      return;
    }
    try {
      const res = await mutation.mutateAsync({
        targets: list,
        scan_mode: scanMode,
        recon_mode: reconMode,
        scan_intensity: scanIntensity,
        instruction: instruction.trim() || undefined,
        name: name.trim() || undefined,
      });
      onOpenChange(false);
      setTargets("");
      setInstruction("");
      setName("");
      setReconMode("active");
      setScanIntensity("active");
      if (res?.instance_id) navigate(`/instances`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New scan</DialogTitle>
          <DialogDescription>
            Authorize one or more targets and choose a scan profile.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="targets">Targets</Label>
            <textarea
              id="targets"
              value={targets}
              onChange={(e) => setTargets(e.target.value)}
              placeholder="example.com&#10;10.0.0.0/24&#10;https://api.example.com"
              required
              rows={4}
              className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
            <p className="text-xs text-muted-foreground">
              One per line or comma-separated. Only test assets you are
              authorized to scan.
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>Mode</Label>
              <Select value={scanMode} onValueChange={setScanMode}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="single">Single target</SelectItem>
                  <SelectItem value="wildcard">Wildcard / multi</SelectItem>
                  <SelectItem value="dast">DAST</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="name">Name (optional)</Label>
              <Input
                id="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="prod-edge sweep"
              />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2">
              <Label>Recon access</Label>
              <Select
                value={reconMode}
                onValueChange={(v) => setReconMode(v as ActivityMode)}
                disabled={scanIntensity === "passive"}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="active">Active allowed</SelectItem>
                  <SelectItem value="passive">Passive only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Testing access</Label>
              <Select
                value={scanIntensity}
                onValueChange={(v) => {
                  const next = v as ActivityMode;
                  setScanIntensity(next);
                  if (next === "passive") setReconMode("passive");
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="active">Active allowed</SelectItem>
                  <SelectItem value="passive">Passive only</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="instruction">Instruction (optional)</Label>
            <textarea
              id="instruction"
              value={instruction}
              onChange={(e) => setInstruction(e.target.value)}
              rows={4}
              placeholder={
                "Multiple lines are supported — e.g.\nFocus on auth + injection; skip noisy enumeration.\nCreds: admin@example.com / hunter2 (role: admin)\nSecond account: user@example.com / pass123 (role: member)"
              }
              className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm font-mono shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            />
          </div>
          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={mutation.isPending || !targets.trim()}
            >
              {mutation.isPending ? "Starting…" : "Start scan"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
