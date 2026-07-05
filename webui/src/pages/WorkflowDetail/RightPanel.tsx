import { useEffect, useState, Component, type ReactNode, type ErrorInfo } from 'react';
import { Copy, Sparkles, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Workflow, WorkflowExecution, WorkflowNode } from '@/api/workflow';
import { useConfirm } from '@/components/common/ConfirmDialog';
import OverviewTab from './tabs/OverviewTab';
import ChatTab from './tabs/ChatTab';
import RunTab from './tabs/RunTab';
import IntegrationTab from './tabs/IntegrationTab';

// ─────────────────────────────────────────────
// Error boundary helpers
// ─────────────────────────────────────────────

function ErrorDisplay({ error, onRetry }: { error: Error; onRetry: () => void }) {
  const { t } = useTranslation('workflow');
  return (
    <div className="p-4 text-xs text-red-600 space-y-2">
      <p className="font-semibold">{t('detail.rightPanel.renderError')}</p>
      <pre className="whitespace-pre-wrap bg-red-50 rounded p-2 overflow-auto max-h-60">
        {error.message}
        {'\n'}
        {error.stack}
      </pre>
      <button
        onClick={onRetry}
        className="text-red-600 underline"
      >
        {t('common:button.retry')}
      </button>
    </div>
  );
}

class TabErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[TabErrorBoundary]', error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        <ErrorDisplay
          error={this.state.error}
          onRetry={() => this.setState({ error: null })}
        />
      );
    }
    return this.props.children;
  }
}

// ─────────────────────────────────────────────
// RightPanel
// ─────────────────────────────────────────────

type TabId = 'chat' | 'overview' | 'run' | 'integration';

interface RightPanelProps {
  workflow: Workflow;
  latestExecution?: WorkflowExecution | null;
  open: boolean;
  width?: number;
  onLatestExecutionChange?: (execution: WorkflowExecution | null) => void;
  onExecutionSettled?: () => void;
  onWorkflowUpdated?: (updated: Workflow) => void;
  onFirstMessageSent?: () => void;
  /** Currently selected node — passed to ChatTab to show reference chip in input */
  selectedNode?: WorkflowNode | null;
  onDeselectNode?: () => void;
  onDelete?: () => Promise<void>;
  onClone?: () => Promise<void>;
}

export default function RightPanel({
  workflow, latestExecution, open, width = 320,
  onLatestExecutionChange,
  onExecutionSettled,
  onWorkflowUpdated,
  onFirstMessageSent,
  selectedNode, onDeselectNode,
  onDelete,
  onClone,
}: RightPanelProps) {
  const { t } = useTranslation('workflow');
  const confirm = useConfirm();
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [deleting, setDeleting] = useState(false);
  const [cloning, setCloning] = useState(false);
  const isBuiltin = workflow.source === 'project';

  useEffect(() => {
    if (isBuiltin && activeTab === 'chat') {
      setActiveTab('overview');
    }
  }, [activeTab, isBuiltin]);

  const handleDelete = async () => {
    const ok = await confirm({
      title: t('detail.rightPanel.deleteConfirmTitle'),
      description: t('detail.rightPanel.deleteConfirmDesc', { name: workflow.name }),
      confirmText: t('detail.rightPanel.deleteConfirmText'),
      variant: 'danger',
    });
    if (!ok || !onDelete) return;
    setDeleting(true);
    try {
      await onDelete();
    } finally {
      setDeleting(false);
    }
  };

  const handleClone = async () => {
    if (!onClone) return;
    setCloning(true);
    try {
      await onClone();
    } finally {
      setCloning(false);
    }
  };

  const TABS: { id: TabId; label: string }[] = [
    { id: 'overview',     label: t('detail.rightPanel.tabOverview') },
    ...(!isBuiltin ? [{ id: 'chat' as const, label: t('detail.rightPanel.tabChat') }] : []),
    { id: 'run',          label: t('detail.rightPanel.tabRun') },
    { id: 'integration',  label: t('detail.rightPanel.tabIntegration') },
  ];

  return (
    <div
      className="flex flex-col bg-white border-l border-gray-200 flex-shrink-0 overflow-hidden transition-[width] duration-300 ease-in-out"
      style={{ width: open ? width : 0 }}
    >
      {/* Tab bar */}
      <div className="flex border-b border-gray-100 flex-shrink-0">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex-1 py-3 text-xs font-medium transition-colors relative ${
              activeTab === tab.id ? 'text-red-600' : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            {tab.label}
            {activeTab === tab.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-red-600 rounded-full" />
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
        {isBuiltin && (
          <div className="mx-4 mt-4 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 text-xs text-blue-700 leading-5">
            <div className="flex items-start gap-2">
              <Sparkles className="w-3.5 h-3.5 mt-0.5 shrink-0" />
              <span>{t('detail.rightPanel.builtinReadonlyHint')}</span>
            </div>
          </div>
        )}
        {activeTab === 'chat' && (
          <ChatTab
            workflow={workflow}
            onLatestExecutionChange={onLatestExecutionChange}
            onWorkflowUpdated={onWorkflowUpdated}
            onFirstMessageSent={onFirstMessageSent}
            selectedNode={selectedNode}
            onNodeRefDismiss={onDeselectNode}
          />
        )}
        {activeTab === 'overview' && <OverviewTab workflow={workflow} />}
        {activeTab === 'run' && (
          <TabErrorBoundary>
            <RunTab
              workflow={workflow}
              latestExecution={latestExecution ?? null}
              onLatestExecutionChange={onLatestExecutionChange}
              onExecutionSettled={onExecutionSettled}
            />
          </TabErrorBoundary>
        )}
        {activeTab === 'integration' && (
          <TabErrorBoundary>
            <IntegrationTab workflow={workflow} />
          </TabErrorBoundary>
        )}
      </div>

      {/* 底部操作按钮 */}
      {(onClone || onDelete) && (
        <div className="flex justify-end gap-2 px-4 py-3 border-t border-gray-100 flex-shrink-0">
          {onClone && (
            <button
              onClick={handleClone}
              disabled={cloning}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-blue-700 border border-blue-200 rounded-lg hover:bg-blue-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Copy className="w-3.5 h-3.5" />
              {cloning ? t('detail.rightPanel.cloning') : t('detail.rightPanel.cloneWorkflow')}
            </button>
          )}
          {onDelete && (
          <button
            onClick={handleDelete}
            disabled={deleting}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-red-600 border border-red-200 rounded-lg hover:bg-red-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            {deleting ? t('detail.rightPanel.deleting') : t('detail.rightPanel.deleteWorkflow')}
          </button>
          )}
        </div>
      )}
    </div>
  );
}
