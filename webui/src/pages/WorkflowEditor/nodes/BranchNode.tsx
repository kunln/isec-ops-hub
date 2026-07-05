import { memo } from 'react';
import { useTranslation } from 'react-i18next';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { GitBranch, Info } from 'lucide-react';

interface BranchNodeData {
  label?: string;
  description?: string;
  select_key?: string;
  join?: string;
  join_mode?: string;
  bg?: string;
  border?: string;
  text?: string;
}

export default memo(function BranchNode({ data, selected }: NodeProps) {
  const { t } = useTranslation('workflow');
  const nodeData = data as BranchNodeData;
  
  return (
    <div
      className={`
        px-4 py-3 rounded-lg border-2 shadow-md min-w-[180px]
        ${nodeData.bg || ''} ${nodeData.border || ''}
        ${selected ? 'ring-2 ring-yellow-400 ring-offset-2' : ''}
        transition-all duration-200
      `}
    >
      {/* Input Handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 !bg-yellow-500 !border-2 !border-white"
      />

      {/* Node Header */}
      <div className="flex items-center gap-2 mb-2">
        <GitBranch className={`w-4 h-4 ${nodeData.text || ''}`} />
        <div className="flex-1">
          <div className={`font-semibold text-sm ${nodeData.text || ''}`}>{t('editor.nodeTypes.branch')}</div>
          <div className="text-xs text-gray-600 font-mono">{nodeData.label || ''}</div>
        </div>
      </div>

      {/* Node Description */}
      {nodeData.description && (
        <div className="flex items-start gap-1 mt-2 p-2 bg-white rounded border border-gray-200">
          <Info className="w-3 h-3 text-gray-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-gray-600 line-clamp-2">{nodeData.description}</p>
        </div>
      )}

      {/* Select Key */}
      {nodeData.select_key && (
        <div className="mt-2 p-2 bg-white rounded border border-gray-200">
          <div className="text-xs text-gray-500">{t('editor.branchKeyLabel')}</div>
          <div className="text-xs font-mono text-gray-800 mt-0.5">{nodeData.select_key}</div>
        </div>
      )}

      {/* Join Info */}
      {nodeData.join && (
        <div className="mt-2 flex items-center gap-2 text-xs text-yellow-700">
          <span className="px-2 py-0.5 bg-yellow-200 rounded-full font-medium">
            Join: {nodeData.join_mode || 'flat'}
          </span>
        </div>
      )}

      {/* Multiple Output Handles for branches */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="branch-1"
        className="w-3 h-3 !bg-yellow-500 !border-2 !border-white"
        style={{ left: '33%' }}
      />
      <Handle
        type="source"
        position={Position.Bottom}
        id="branch-2"
        className="w-3 h-3 !bg-yellow-500 !border-2 !border-white"
        style={{ left: '66%' }}
      />
    </div>
  );
});
