import { cn } from "cn"

/**
 * A statement, condition or rule snippet. Always rendered as text: it comes
 * from agents or config files and must never be treated as markup.
 */
export function Sql({
  children,
  className,
  clamp,
}: {
  children: string
  className?: string
  clamp?: boolean
}) {
  return (
    <pre
      className={cn(
        "rounded-md border bg-muted/50 px-2.5 py-1.5 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap",
        clamp && "line-clamp-4 max-w-[48ch] min-w-[24ch]",
        className
      )}
      title={clamp ? children : undefined}
    >
      {children}
    </pre>
  )
}
