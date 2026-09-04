import { useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

export const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const;
export const DEFAULT_PAGE_SIZE = 50;

export interface PaginationProps {
  totalItems: number;
  /** 1-indexed current page. */
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  className?: string;
}

/**
 * Build the page-number sequence to render. Includes 1, the last page, the
 * current page, and its neighbors. Distant gaps are represented by the
 * literal string "ellipsis".
 *
 * Example for current=6, total=99: [1, "ellipsis", 5, 6, 7, "ellipsis", 99].
 */
export function buildPageItems(
  current: number,
  totalPages: number,
): Array<number | "ellipsis"> {
  if (totalPages <= 1) return [1];
  const pages = new Set<number>();
  pages.add(1);
  pages.add(totalPages);
  for (let p = current - 1; p <= current + 1; p += 1) {
    if (p >= 1 && p <= totalPages) pages.add(p);
  }
  const sorted = Array.from(pages).sort((a, b) => a - b);
  const out: Array<number | "ellipsis"> = [];
  for (let i = 0; i < sorted.length; i += 1) {
    const n = sorted[i];
    if (i > 0 && n - sorted[i - 1] > 1) {
      out.push("ellipsis");
    }
    out.push(n);
  }
  return out;
}

/**
 * Pagination control with Prev / 1 2 … N / Next buttons and a page-size
 * selector. Component state is synced to the URL's `?page=` and `?size=`
 * query params, so reloading the page preserves the user's position.
 *
 * The page-size selector is rendered whenever there is at least one
 * item, so users with fewer items than the current page size can still
 * lower the page size to skim faster. The page-number strip is hidden
 * when there is only a single page.
 *
 * Returns `null` only when `totalItems === 0`.
 */
export function Pagination({
  totalItems,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  className,
}: PaginationProps) {
  const [searchParams, setSearchParams] = useSearchParams();

  // Hydrate from URL once on mount + whenever the URL changes externally.
  useEffect(() => {
    const urlPage = Number.parseInt(searchParams.get("page") ?? "", 10);
    const urlSize = Number.parseInt(searchParams.get("size") ?? "", 10);
    if (
      Number.isFinite(urlSize) &&
      (PAGE_SIZE_OPTIONS as readonly number[]).includes(urlSize) &&
      urlSize !== pageSize
    ) {
      onPageSizeChange(urlSize);
    }
    if (Number.isFinite(urlPage) && urlPage >= 1 && urlPage !== page) {
      onPageChange(urlPage);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const totalPages = Math.max(1, Math.ceil(totalItems / Math.max(1, pageSize)));
  const safePage = Math.min(Math.max(1, page), totalPages);

  // Push state changes back into the URL so reload preserves position.
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    let changed = false;
    if (next.get("page") !== String(safePage)) {
      next.set("page", String(safePage));
      changed = true;
    }
    if (next.get("size") !== String(pageSize)) {
      next.set("size", String(pageSize));
      changed = true;
    }
    if (changed) setSearchParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [safePage, pageSize]);

  if (totalItems === 0) return null;

  const items = buildPageItems(safePage, totalPages);
  const showPageStrip = totalPages > 1;

  function go(p: number) {
    const clamped = Math.min(Math.max(1, p), totalPages);
    if (clamped !== safePage) onPageChange(clamped);
  }

  function changeSize(value: string) {
    const n = Number.parseInt(value, 10);
    if (Number.isFinite(n) && (PAGE_SIZE_OPTIONS as readonly number[]).includes(n)) {
      onPageSizeChange(n);
      // Reset to first page when page size changes so the user does not end
      // up past the new last page.
      onPageChange(1);
    }
  }

  return (
    <div
      className={cn(
        "flex flex-col gap-3 border-t border-border px-3 py-2 sm:flex-row sm:items-center sm:justify-between",
        className,
      )}
    >
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>Rows per page</span>
        <Select value={String(pageSize)} onValueChange={changeSize}>
          <SelectTrigger className="h-8 w-20 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {PAGE_SIZE_OPTIONS.map((size) => (
              <SelectItem key={size} value={String(size)}>
                {size}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <span className="ml-2 mono">
          Page {safePage} of {totalPages} · {totalItems} items
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-1">
        {showPageStrip ? (
          <>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={safePage <= 1}
              onClick={() => go(safePage - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft className="h-3.5 w-3.5" />
              Prev
            </Button>
            {items.map((item, i) =>
              item === "ellipsis" ? (
                <span
                  key={`ellipsis-${i}`}
                  className="px-2 text-xs text-muted-foreground"
                  aria-hidden="true"
                >
                  …
                </span>
              ) : (
                <Button
                  key={item}
                  type="button"
                  size="sm"
                  variant={item === safePage ? "default" : "outline"}
                  onClick={() => go(item)}
                  aria-current={item === safePage ? "page" : undefined}
                  aria-label={`Page ${item}`}
                >
                  {item}
                </Button>
              ),
            )}
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={safePage >= totalPages}
              onClick={() => go(safePage + 1)}
              aria-label="Next page"
            >
              Next
              <ChevronRight className="h-3.5 w-3.5" />
            </Button>
          </>
        ) : null}
      </div>
    </div>
  );
}

export default Pagination;
