import type * as React from "react"
import {
  FileCode2Icon,
  HistoryIcon,
  InboxIcon,
  LayoutDashboardIcon,
  ScaleIcon,
  ScrollTextIcon,
  Settings2Icon,
} from "lucide-react"
import { Logo } from "@/components/logo"
import { NavMain, type NavItem } from "@/components/nav-main"
import { NavUser } from "@/components/nav-user"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { useCan } from "@/lib/me"
import { linkClick, type Page } from "@/lib/router"

export const titles: Record<Page, string> = {
  "/": "Overview",
  "/approvals": "Approvals",
  "/decisions": "Decisions",
  "/sessions": "Sessions and undo",
  "/rules": "Rules",
  "/config": "Config",
  "/settings": "Settings",
}

export function AppSidebar({
  current,
  pending,
  onSignOut,
  ...props
}: React.ComponentProps<typeof Sidebar> & {
  current: Page
  pending: number
  onSignOut: () => void
}) {
  const admin = useCan("admin")
  const main: NavItem[] = [
    { title: titles["/"], url: "/", icon: <LayoutDashboardIcon /> },
    { title: titles["/approvals"], url: "/approvals", icon: <InboxIcon />, badge: pending },
    { title: titles["/decisions"], url: "/decisions", icon: <ScrollTextIcon /> },
    { title: titles["/sessions"], url: "/sessions", icon: <HistoryIcon /> },
    { title: titles["/rules"], url: "/rules", icon: <ScaleIcon /> },
    ...(admin ? [{ title: titles["/config"], url: "/config" as const, icon: <FileCode2Icon /> }] : []),
  ]
  const secondary: NavItem[] = [
    { title: titles["/settings"], url: "/settings", icon: <Settings2Icon /> },
  ]
  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton asChild className="data-[slot=sidebar-menu-button]:p-1.5!">
              <a href="/" onClick={(e) => linkClick(e, "/")}>
                <Logo className="size-5!" />
                <span className="font-mono text-base font-semibold tracking-tight">ariodb</span>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain items={main} current={current} />
        <NavMain items={secondary} current={current} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <NavUser onSignOut={onSignOut} />
      </SidebarFooter>
    </Sidebar>
  )
}
