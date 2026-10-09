// The shadcn data-table pattern on TanStack Table v9: sortable headers and
// client-side pages over rows the server has already filtered.
import { useState, type ReactNode } from "react"
import {
  createColumnHelper,
  createPaginatedRowModel,
  createSortedRowModel,
  FlexRender,
  rowPaginationFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_basic,
  sortFn_text,
  tableFeatures,
  useTable,
  type ColumnDef,
  type RowData,
} from "@tanstack/react-table"
import {
  ArrowDownIcon,
  ArrowUpDownIcon,
  ArrowUpIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ChevronsLeftIcon,
  ChevronsRightIcon,
} from "lucide-react"
import { cn } from "cn"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

// Only the features used here are registered, so the rest of TanStack Table
// is left out of the bundle.
const features = tableFeatures({
  rowPaginationFeature,
  rowSortingFeature,
  paginatedRowModel: createPaginatedRowModel(),
  sortedRowModel: createSortedRowModel(),
  sortFns: { basic: sortFn_basic, text: sortFn_text, alphanumeric: sortFn_alphanumeric },
})

export type Features = typeof features
export type Columns<T extends RowData> = Array<ColumnDef<Features, T, any>>

export function columnHelper<T extends RowData>() {
  return createColumnHelper<Features, T>()
}

export function DataTable<T extends RowData>({
  columns,
  data,
  empty,
  pageSize = 20,
  getRowId,
  rowClassName,
  minWidth,
}: {
  columns: Columns<T>
  data: T[]
  empty: ReactNode
  pageSize?: number
  getRowId?: (row: T) => string
  rowClassName?: (row: T) => string | undefined
  /** Below this width the table scrolls sideways instead of squeezing its columns. */
  minWidth?: string
}) {
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize })
  const table = useTable({
    features,
    data,
    columns,
    getRowId: getRowId ? (row: T) => getRowId(row) : undefined,
    initialState: { sorting: [] },
    state: { pagination },
    onPaginationChange: setPagination,
    autoResetPageIndex: true,
  })
  const pages = table.getPageCount()
  const total = data.length

  return (
    <div className="flex flex-col gap-3">
      <div className="overflow-x-auto rounded-lg border">
        <Table style={minWidth ? { minWidth } : undefined}>
          <TableHeader className="bg-muted/60">
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id} className="hover:bg-transparent">
                {group.headers.map((header) => {
                  const sortable = header.column.getCanSort()
                  const sorted = header.column.getIsSorted()
                  return (
                    <TableHead
                      key={header.id}
                      colSpan={header.colSpan}
                      aria-sort={
                        sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined
                      }
                    >
                      {header.isPlaceholder ? null : sortable ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="-ml-2 h-7 px-2 text-xs font-medium text-muted-foreground"
                          onClick={header.column.getToggleSortingHandler()}
                        >
                          <FlexRender header={header} />
                          {sorted === "asc" ? (
                            <ArrowUpIcon />
                          ) : sorted === "desc" ? (
                            <ArrowDownIcon />
                          ) : (
                            <ArrowUpDownIcon className="opacity-40" />
                          )}
                        </Button>
                      ) : (
                        <span className="text-xs font-medium text-muted-foreground">
                          <FlexRender header={header} />
                        </span>
                      )}
                    </TableHead>
                  )
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id} className={cn(rowClassName?.(row.original))}>
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.id} className="align-top">
                      <FlexRender cell={cell} />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={columns.length} className="h-24 text-center text-muted-foreground">
                  {empty}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {pages > 1 && (
        <div className="flex items-center justify-between gap-2 text-sm">
          <div className="text-muted-foreground">
            {total} rows
          </div>
          <div className="flex items-center gap-2">
            <span className="font-medium tabular-nums">
              Page {pagination.pageIndex + 1} of {pages}
            </span>
            <Button
              variant="outline"
              size="icon"
              className="hidden sm:flex"
              onClick={() => table.setPageIndex(0)}
              disabled={!table.getCanPreviousPage()}
            >
              <span className="sr-only">First page</span>
              <ChevronsLeftIcon />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
            >
              <span className="sr-only">Previous page</span>
              <ChevronLeftIcon />
            </Button>
            <Button
              variant="outline"
              size="icon"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
            >
              <span className="sr-only">Next page</span>
              <ChevronRightIcon />
            </Button>
            <Button
              variant="outline"
              size="icon"
              className="hidden sm:flex"
              onClick={() => table.setPageIndex(pages - 1)}
              disabled={!table.getCanNextPage()}
            >
              <span className="sr-only">Last page</span>
              <ChevronsRightIcon />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
