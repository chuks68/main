import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

export interface LineageNode {
  id: string;
  label: string;
  parentId?: string | null;
  children: string[];
  depth?: number;
  x?: number;
  y?: number;
}

export interface LineageEdge {
  id?: string;
  from: string;
  to: string;
}

export interface LayoutNode {
  id: string;
  x: number;
  y: number;
  width: number;
  height: number;
  layer: number;
}

export interface LayoutEdge {
  id: string;
  from: string;
  to: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

export interface LayoutResult {
  nodes: LayoutNode[];
  edges: LayoutEdge[];
  width: number;
  height: number;
}

export interface LineageGraphProps {
  nodes: LineageNode[];
  onNodeSelect?: (node: LineageNode) => void;
  /** Optional callback to open node details (Enter). */
  onNodeOpen?: (node: LineageNode) => void;
  /** Viewport height for the virtualized list. Defaults to 400. */
  viewportHeight?: number;
  /** Row height for the virtualized list. Defaults to 32. */
  rowHeight?: number;
  edges: LineageEdge[];
  workerFactory?: () => Worker;
}

interface RenderedNode {
  id: string;
  label: string;
  depth: number;
  parentId: string | null;
  children: string[];
  index: number;
}

function buildFlatList(nodes: LineageNode[]): RenderedNode[] {
  const byId = new Map<string, LineageNode>();
  for (const n of nodes) byId.set(n.id, n);

  const roots = nodes.filter(
    (n) => !n.parentId || !byId.has(n.parentId),
  );

  const result: RenderedNode[] = [];
  const visited = new Set<string>();

  const walk = (node: LineageNode, depth: number, parentId: string | null) => {
    if (visited.has(node.id)) return;
    visited.add(node.id);
    const children = (node.children || []).filter((id) => byId.has(id));
    const index = result.length;
    result.push({
      id: node.id,
      label: node.label,
      depth,
      parentId,
      children,
      index,
    });
    for (const childId of children) {
      const child = byId.get(childId);
      if (child) walk(child, depth + 1, node.id);
    }
  };

  for (const root of roots) walk(root, 1, null);
  // Append any orphan nodes not reached via children relationships.
  for (const n of nodes) {
    if (!visited.has(n.id)) walk(n, 1, null);
  }
  return result;
}

function getFocusableStyle(focused: boolean): React.CSSProperties {
  return {
    outline: focused ? '3px solid #1a73e8' : 'transparent',
    outlineOffset: focused ? '-3px' : 0,
    boxShadow: focused ? 'inset 0 0 0 1px #fff' : 'none',
    borderRadius: 4,
  };
}

export const LineageGraph: React.FC<LineageGraphProps> = ({
  nodes,
  onNodeSelect,
  onNodeOpen,
  viewportHeight = 400,
  rowHeight = 32,
}) => {
  const flatNodes = useMemo(() => buildFlatList(nodes), [nodes]);
  const indexById = useMemo(() => {
    const m = new Map<string, number>();
    flatNodes.forEach((n, i) => m.set(n.id, i));
    return m;
  }, [flatNodes]);

  const [focusedId, setFocusedId] = useState<string | null>(
    flatNodes.length > 0 ? flatNodes[0].id : null,
  );
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(flatNodes.filter((n) => n.children.length > 0).map((n) => n.id)),
  );
  const [scrollTop, setScrollTop] = useState(0);
  const containerRef = useRef<HTMLElement | null>(null);
  const itemRefs = useRef<Map<string, HTMLElement>>(new Map());

  // Keep focus valid when nodes change.
  useEffect(() => {
    if (focusedId && !indexById.has(focusedId)) {
      setFocusedId(flatNodes.length > 0 ? flatNodes[0].id : null);
    }
  }, [flatNodes, indexById, focusedId]);

  const focusNode = useCallback((id: string) => {
    setFocusedId(id);
    const el = itemRefs.current.get(id);
    if (el) {
      el.focus();
      // Ensure the focused item is visible in the virtualized viewport.
      const idx = indexById.get(id);
      if (idx !== undefined) {
        const top = idx * rowHeight;
        const bottom = top + rowHeight;
        if (top < scrollTop) {
          setScrollTop(top);
        } else if (bottom > scrollTop + viewportHeight) {
          setScrollTop(bottom - viewportHeight);
        }
      }
    }
  }, [indexById, rowHeight, scrollTop, viewportHeight]);

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLElement>) => {
      if (!focusedId) return;
      const currentIdx = indexById.get(focusedId);
      if (currentIdx === undefined) return;
      const current = flatNodes[currentIdx];
      const isExpanded = expanded.has(current.id);

      switch (event.key) {
        case 'ArrowDown': {
          event.preventDefault();
          const next = flatNodes[currentIdx + 1];
          if (next) focusNode(next.id);
          break;
        }
        case 'ArrowUp': {
          event.preventDefault();
          const prev = flatNodes[currentIdx - 1];
          if (prev) focusNode(prev.id);
          break;
        }
        case 'ArrowRight': {
          event.preventDefault();
          if (current.children.length > 0) {
            if (!isExpanded) {
              setExpanded((prev) => {
                const next = new Set(prev);
                next.add(current.id);
                return next;
              });
            } else {
              const childId = current.children[0];
              if (indexById.has(childId)) focusNode(childId);
            }
          }
          break;
        }
        case 'ArrowLeft': {
          event.preventDefault();
          if (current.children.length > 0 && isExpanded) {
            setExpanded((prev) => {
              const next = new Set(prev);
              next.delete(current.id);
              return next;
            });
          } else if (current.parentId) {
            focusNode(current.parentId);
          }
          break;
        }
        case 'Home': {
          event.preventDefault();
          if (flatNodes[0]) focusNode(flatNodes[0].id);
          break;
        }
        case 'End': {
          event.preventDefault();
          const last = flatNodes[flatNodes.length - 1];
          if (last) focusNode(last.id);
          break;
        }
        case 'Enter':
        case ' ': {
          event.preventDefault();
          const original = nodes.find((n) => n.id === current.id);
          if (original) {
            onNodeSelect?.(original);
            onNodeOpen?.(original);
          }
          break;
        }
        default:
          break;
      }
    },
    [nodes, focusedId, indexById, flatNodes, expanded, focusNode, onNodeSelect, onNodeOpen],
  );

  const visibleStart = Math.max(0, Math.floor(scrollTop / rowHeight) - 2);
  const visibleEnd = Math.min(
    flatNodes.length,
    Math.ceil((scrollTop + viewportHeight) / rowHeight) + 2,
  );
  const visibleNodes = flatNodes.slice(visibleStart, visibleEnd);

  const handleScroll = useCallback((event: React.UIEvent<HTMLElement>) => {
    setScrollTop(event.currentTarget.scrollTop);
  }, []);

  return (
    <div
      ref={containerRef}
      role="tree"
      aria-label="Lineage graph"
      onKeyDown={handleKeyDown}
      onFocus={() => {
        if (focusedId) {
          const el = itemRefs.current.get(focusedId);
          el?.focus();
        }
      }}
      style={{
        overflowY: 'auto',
        height: viewportHeight,
        position: 'relative',
        border: '1px solid #d0d7de',
        borderRadius: 6,
        padding: 0,
        margin: 0,
      }}
      onScroll={handleScroll}
      tabIndex={-1}
    >
      <div style={{ height: flatNodes.length * rowHeight, position: 'relative' }}>
        {visibleNodes.map((node) => {
          const isExpanded = expanded.has(node.id);
          const isFocused = focusedId === node.id;
          const top = node.index * rowHeight;
          return (
            <div
              key={node.id}
              ref={(el) => {
                if (el) itemRefs.current.set(node.id, el);
                else itemRefs.current.delete(node.id);
              }}
              role="treeitem"
              aria-level={node.depth}
              aria-expanded={node.children.length > 0 ? isExpanded : undefined}
              aria-selected={isFocused}
              aria-label={`${node.label}, depth ${node.depth}`}
              tabIndex={isFocused ? 0 : -1}
              onClick={() => {
                const original = nodes.find((n) => n.id === node.id);
                if (original) onNodeSelect?.(original);
              }}
              onFocus={() => setFocusedId(node.id)}
              style={{
                position: 'absolute',
                top,
                left: 0,
                right: 0,
                height: rowHeight,
                display: 'flex',
                alignItems: 'center',
                paddingLeft: 8 + (node.depth - 1) * 16,
                paddingRight: 8,
                fontSize: 13,
                color: '#1f2937',
                background: isFocused ? '#e8f0fe' : 'transparent',
                cursor: 'pointer',
                userSelect: 'none',
                ...getFocusableStyle(isFocused),
              }}
            >
              {node.children.length > 0 ? (
                <span aria-hidden="true" style={{ width: 12, display: 'inline-block' }}>
                  {isExpanded ? '▾' : '▶' }
                </span>
              ) : (
                <span aria-hidden="true" style={{ width: 12, display: 'inline-block' }} />
              )}
              <span>{node.label}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

type Status = "loading" | "rendered" | "error";

export default function LineageGraphSvg({ nodes, edges, workerFactory }: LineageGraphProps) {
  const [status, setStatus] = useState<Status>("loading");
  const [layout, setLayout] = useState<LayoutResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const workerRef = useRef<Worker | null>(null);

  useEffect(() => {
    setStatus("loading");
    setLayout(null);
    setErrorMessage(null);

    if (nodes.length === 0) {
      setLayout({ nodes: [], edges: [], width: 0, height: 0 });
      setStatus("rendered");
      return undefined;
    }

    const factory =
      workerFactory ??
      (() =>
        new Worker(new URL("../workers/lineage-renderer.worker.ts", import.meta.url), {
          type: "module",
        }));

    let worker: Worker;
    try {
      worker = factory();
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : String(err));
      setStatus("error");
      return undefined;
    }
    workerRef.current = worker;

    const handleMessage = (event: MessageEvent) => {
      const data = event.data as
        | { type: "layout-result"; result: LayoutResult }
        | { type: "layout-error"; message: string }
        | undefined;
      if (!data) return;
      if (data.type === "layout-result") {
        setLayout(data.result);
        setStatus("rendered");
      } else if (data.type === "layout-error") {
        setErrorMessage(data.message);
        setStatus("error");
      }
    };

    const handleError = (event: ErrorEvent) => {
      setErrorMessage(event.message || "Worker error");
      setStatus("error");
    };

    worker.addEventListener("message", handleMessage);
    worker.addEventListener("error", handleError as EventListener);
    worker.postMessage({ type: "layout", payload: { nodes, edges } });

    return () => {
      worker.removeEventListener("message", handleMessage);
      worker.removeEventListener("error", handleError as EventListener);
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
    };
  }, [nodes, edges, workerFactory]);

  if (status === "loading") {
    return (
      <div data-testid="lineage-loading" role="status">
        Loading graph…
      </div>
    );
  }

  if (status === "error") {
    return (
      <div data-testid="lineage-error" role="alert">
        Error: {errorMessage ?? "Unknown error"}
      </div>
    );
  }

  const width = layout?.width ?? 0;
  const height = layout?.height ?? 0;

  return (
    <div data-testid="lineage-graph">
      <svg
        role="img"
        aria-label="Lineage graph"
        width={width || 1}
        height={height || 1}
        viewBox={`0 0 ${width || 1} ${height || 1}`}
      >
        {layout?.edges.map((edge) => (
          <line
            key={edge.id}
            data-testid={"lineage-edge"}
            x1={edge.x1}
            y1={edge.y1}
            x2={edge.x2}
            y2={edge.y2}
            stroke="#888"
            strokeWidth={1}
          />
        ))}
        {layout?.nodes.map((node) => {
          const label = nodes.find((n) => n.id === node.id)?.label ?? node.id;
          return (
            <g key={node.id} data-testid="lineage-node">
              <rect
                x={node.x}
                y={node.y}
                width={node.width}
                height={node.height}
                rx={4}
                fill="#fff"
                stroke="#333"
              />
              <text
                x={node.x + node.width / 2}
                y={node.y + node.height / 2}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={12}
              >
                {label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}