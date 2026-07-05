import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Workflow } from '@/api/workflow';
import CreateChatTab from './CreateChatTab';
import CreateOverviewTab from './CreateOverviewTab';

type TabId = 'chat' | 'overview';

interface CreateRightPanelProps {
  workflow: Workflow | null;
  open: boolean;
  width?: number;
  onWorkflowCreated: (workflow: Workflow) => void;
}

export default function CreateRightPanel({
  workflow,
  open,
  width = 320,
  onWorkflowCreated,
}: CreateRightPanelProps) {
  const { t } = useTranslation('workflow');
  const [activeTab, setActiveTab] = useState<TabId>('chat');

  const TABS: { id: TabId; label: string }[] = [
    { id: 'overview', label: t('create.rightPanel.tabOverview') },
    { id: 'chat', label: t('create.rightPanel.tabChat') },
  ];

  return (
    <div
      className="flex flex-col bg-white border-l border-gray-200 flex-shrink-0 overflow-hidden transition-[width] duration-300 ease-in-out"
      style={{ width: open ? width : 0 }}
    >
      <div className="flex border-b border-gray-100 flex-shrink-0">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`
              flex-1 py-3 text-xs font-medium transition-colors relative
              ${activeTab === tab.id ? 'text-red-600' : 'text-gray-500 hover:text-gray-700'}
            `}
          >
            {tab.label}
            {activeTab === tab.id && (
              <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-red-600 rounded-full" />
            )}
          </button>
        ))}
      </div>

      <div className="flex-1 min-h-0 overflow-hidden flex flex-col">
        {activeTab === 'chat' && (
          <CreateChatTab onWorkflowCreated={onWorkflowCreated} />
        )}
        {activeTab === 'overview' && (
          <CreateOverviewTab workflow={workflow} />
        )}
      </div>
    </div>
  );
}
