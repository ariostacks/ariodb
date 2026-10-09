import { useEffect, useRef } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Textarea } from "@/components/ui/textarea"

/**
 * Shown when the browser will not let the page write to the clipboard
 * (it refuses over plain HTTP from anywhere but localhost).
 */
export function CopyDialog({
  text,
  title,
  onClose,
}: {
  text: string | null
  title: string
  onClose: () => void
}) {
  const area = useRef<HTMLTextAreaElement>(null)
  useEffect(() => {
    if (text !== null) window.setTimeout(() => area.current?.select(), 50)
  }, [text])
  return (
    <Dialog open={text !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            This browser did not allow copying from the page. Select the text and copy it yourself.
          </DialogDescription>
        </DialogHeader>
        <Textarea
          ref={area}
          readOnly
          value={text ?? ""}
          rows={12}
          className="font-mono text-xs"
          aria-label={title}
        />
      </DialogContent>
    </Dialog>
  )
}
