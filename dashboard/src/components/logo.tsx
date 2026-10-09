import { DatabaseZapIcon } from "lucide-react"
import { cn } from "cn"

export function Logo({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "flex size-6 items-center justify-center rounded-md bg-teal-700 text-white dark:bg-teal-500 dark:text-teal-950",
        className
      )}
      aria-hidden="true"
    >
      <DatabaseZapIcon className="size-4" />
    </div>
  )
}
