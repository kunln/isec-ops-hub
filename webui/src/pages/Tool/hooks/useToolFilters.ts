import { useState, useMemo } from 'react';
import type { Tool } from '@/api/tool';
import type { TabKey, SortState, SortField, ColumnFilters } from '../types';
import { EMPTY_FILTERS, } from '../types';
import { TABS, SOURCE_SORT_ORDER, CATEGORY_LABEL_KEY, PAGE_SIZE } from '../constants';

export function useToolFilters(tools: Tool[]) {
  const [activeTab, setActiveTab] = useState<TabKey>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [sort, setSort] = useState<SortState>({ field: 'source', dir: 'asc' });
  const [filters, setFilters] = useState<ColumnFilters>(EMPTY_FILTERS);

  const tabCounts = useMemo(() => {
    const counts: Record<string, number> = { all: 0, mcp: 0, api: 0, local: 0 };
    tools.forEach((t) => {
      counts.all++;
      if (t.source === 'mcp') counts.mcp++;
      else if (t.source === 'api') counts.api++;
      else if (t.source === 'plugin_py') counts.local++;
    });
    return counts;
  }, [tools]);

  const filterOptions = useMemo(() => {
    const cats = new Set<string>();
    const sources = new Set<string>();
    const sourceNames = new Set<string>();
    tools.forEach((t) => {
      cats.add(t.category);
      sources.add(t.source);
      sourceNames.add(t.source_name || 'Flocks');
    });
    return {
      category: Array.from(cats).sort(),
      source: Array.from(sources).sort((a, b) => (SOURCE_SORT_ORDER[a] ?? 99) - (SOURCE_SORT_ORDER[b] ?? 99)),
      source_name: Array.from(sourceNames).sort(),
      enabled: ['true', 'false'],
    };
  }, [tools]);

  const processedTools = useMemo(() => {
    let result = [...tools];

    const tabConfig = TABS.find((tab) => tab.key === activeTab);
    if (tabConfig?.sourceFilter) {
      const sf = tabConfig.sourceFilter;
      const allowed: string[] = Array.isArray(sf) ? sf : [sf];
      result = result.filter((tool) => allowed.includes(tool.source));
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (t) =>
          t.name.toLowerCase().includes(q) ||
          t.description.toLowerCase().includes(q) ||
          (t.source_name || '').toLowerCase().includes(q),
      );
    }

    if (filters.category.size > 0) result = result.filter((t) => filters.category.has(t.category));
    if (filters.source.size > 0) result = result.filter((t) => filters.source.has(t.source));
    if (filters.source_name.size > 0) result = result.filter((t) => filters.source_name.has(t.source_name || 'Flocks'));
    if (filters.enabled.size > 0) result = result.filter((t) => filters.enabled.has(String(t.enabled)));

    result.sort((a, b) => {
      let cmp = 0;
      switch (sort.field) {
        case 'category': {
          const la = CATEGORY_LABEL_KEY[a.category] ?? a.category;
          const lb = CATEGORY_LABEL_KEY[b.category] ?? b.category;
          cmp = la.localeCompare(lb);
          break;
        }
        case 'source':
          cmp = (SOURCE_SORT_ORDER[a.source] ?? 99) - (SOURCE_SORT_ORDER[b.source] ?? 99);
          break;
        case 'source_name':
          cmp = (a.source_name || 'Flocks').localeCompare(b.source_name || 'Flocks', 'zh');
          break;
        case 'enabled':
          cmp = a.enabled === b.enabled ? 0 : a.enabled ? -1 : 1;
          break;
      }
      return sort.dir === 'desc' ? -cmp : cmp;
    });

    return result;
  }, [tools, activeTab, searchQuery, filters, sort]);

  const totalPages = Math.ceil(processedTools.length / PAGE_SIZE);
  const paginatedTools = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return processedTools.slice(start, start + PAGE_SIZE);
  }, [processedTools, currentPage]);

  const handleTabChange = (tab: TabKey) => {
    setActiveTab(tab);
    setCurrentPage(1);
    setSearchQuery('');
    setFilters(EMPTY_FILTERS);
    setSort({ field: 'source', dir: 'asc' });
  };

  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    setCurrentPage(1);
  };

  const toggleSort = (field: SortField) => {
    setSort((prev) =>
      prev.field === field
        ? { field, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { field, dir: 'asc' },
    );
    setCurrentPage(1);
  };

  const toggleFilter = (column: keyof ColumnFilters, value: string) => {
    setFilters((prev) => {
      const next = new Set(prev[column]);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return { ...prev, [column]: next };
    });
    setCurrentPage(1);
  };

  const clearFilter = (column: keyof ColumnFilters) => {
    setFilters((prev) => ({ ...prev, [column]: new Set() }));
    setCurrentPage(1);
  };

  return {
    activeTab,
    searchQuery,
    sort,
    filters,
    filterOptions,
    tabCounts,
    processedTools,
    paginatedTools,
    currentPage,
    totalPages,
    handleTabChange,
    handleSearchChange,
    toggleSort,
    toggleFilter,
    clearFilter,
    setCurrentPage,
  };
}
