import type { ToolSource } from '@/api/tool';

export type TabKey = 'all' | 'mcp' | 'api' | 'local';

export interface TabConfig {
  key: TabKey;
  label: string;
  icon: React.ReactNode;
  sourceFilter?: ToolSource | ToolSource[];
}

export type SortField = 'category' | 'source' | 'source_name' | 'enabled';
export type SortDir = 'asc' | 'desc';

export interface SortState {
  field: SortField;
  dir: SortDir;
}

export interface ColumnFilters {
  category: Set<string>;
  source: Set<string>;
  source_name: Set<string>;
  enabled: Set<string>;
}

export const EMPTY_FILTERS: ColumnFilters = {
  category: new Set(),
  source: new Set(),
  source_name: new Set(),
  enabled: new Set(),
};

export type AddToolType = 'mcp' | 'api' | 'generate' | null;
