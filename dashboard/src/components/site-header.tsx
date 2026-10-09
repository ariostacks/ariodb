import { InboxIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import { SidebarTrigger } from "@/components/ui/sidebar"
import { linkClick } from "@/lib/router"

export function SiteHeader({ title, pending, onApprovals }: { title: string; pending: number; onApprovals: boolean }) {
  return (
    <header className="sticky top-0 z-10 flex h-(--header-height) shrink-0 items-center gap-2 border-b bg-background/90 backdrop-blur transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height) md:rounded-t-xl">
      <div className="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
        <SidebarTrigger className="-ml-1" />
        <Separator orientation="vertical" className="mx-2 data-[orientation=vertical]:h-4" />
        <h1 className="text-base font-medium">{title}</h1>
        {pending > 0 && !onApprovals && (
          <Button asChild variant="outline" size="sm" className="ml-auto">
            <a href="/approvals" onClick={(e) => linkClick(e, "/approvals")}>
              <InboxIcon />
              <span>
                {pending} waiting<span className="hidden sm:inline"> for approval</span>
              </span>
            </a>
          </Button>
        )}
      </div>
    </header>
  )
}
