import { Link } from "react-router-dom"
import { Button } from "@/components/ui/button"

export default function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 text-center">
      <div className="font-mono text-xs uppercase tracking-wider text-muted-foreground">404</div>
      <h1 className="font-sans text-3xl font-semibold tracking-tight">Page not found</h1>
      <p className="max-w-sm text-sm text-muted-foreground">
        The route you requested does not exist in this console.
      </p>
      <Button asChild variant="outline">
        <Link to="/">Return to overview</Link>
      </Button>
    </div>
  )
}
