import type { ReactNode } from "react"
import {
  SidebarGroup,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { linkClick, type Page } from "@/lib/router"

export type NavItem = { title: string; url: Page; icon: ReactNode; badge?: number }

export function NavMain({
  items,
  current,
  className,
}: {
  items: NavItem[]
  current: Page
  className?: string
}) {
  const { setOpenMobile } = useSidebar()
  return (
    <SidebarGroup className={className}>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.url}>
              <SidebarMenuButton asChild tooltip={item.title} isActive={item.url === current}>
                <a
                  href={item.url}
                  aria-current={item.url === current ? "page" : undefined}
                  onClick={(e) => {
                    linkClick(e, item.url)
                    setOpenMobile(false)
                  }}
                >
                  {item.icon}
                  <span>{item.title}</span>
                </a>
              </SidebarMenuButton>
              {item.badge ? (
                <SidebarMenuBadge
                  className="rounded-full bg-amber-500 px-1.5 text-white peer-data-[active=true]/menu-button:text-white dark:bg-amber-500 dark:text-black"
                  aria-label={`${item.badge} waiting`}
                >
                  {item.badge}
                </SidebarMenuBadge>
              ) : null}
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  )
}
