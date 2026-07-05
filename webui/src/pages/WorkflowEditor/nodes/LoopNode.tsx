import { memo } from 'react';
import { useTranslation } from 'react-i18next';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { RotateCw, Info } from 'lucide-react';

interface LoopNodeData {
  label?: string;
  description?: string;
  code?: string;
  join?: string;
  join_mode?: string;
  bg?: string;
  border?: string;
  text?: string;
}

export default memo(function LoopNode({ data, selected }: NodeProps) {
  const { t } = useTranslation('workflow');
  const nodeData = data as LoopNodeData;
  
  return (
    <div
      className={`
        px-4 py-3 rounded-lg border-2 shadow-md min-w-[180px]
        ${nodeData.bg || ''} ${nodeData.border || ''}
        ${selected ? 'ring-2 ring-purple-400 ring-offset-2' : ''}
        transition-all duration-200
      `}
    >
      {/* Input Handle */}
      <Handle
        type="target"
        position={Position.Top}
        className="w-3 h-3 !bg-purple-500 !border-2 !border-white"
      />

      {/* Node Header */}
      <div className="flex items-center gap-2 mb-2">
        <RotateCw className={`w-4 h-4 ${nodeData.text || ''}`} />
        <div className="flex-1">
          <div className={`font-semibold text-sm ${nodeData.text || ''}`}>{t('editor.nodeTypes.loop')}</div>
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

      {/* Code Preview */}
      {nodeData.code && (
        <div className="mt-2 p-2 bg-gray-900 rounded text-xs font-mono text-gray-300 overflow-hidden">
          <div className="line-clamp-3">{nodeData.code}</div>
        </div>
      )}

      {/* Join Info */}
      {nodeData.join && (
        <div className="mt-2 flex items-center gap-2 text-xs text-purple-700">
          <span className="px-2 py-0.5 bg-purple-200 rounded-full font-medium">
            Join: {nodeData.join_mode || 'flat'}
          </span>
        </div>
      )}

      {/* Output Handles */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="next"
        className="w-3 h-3 !bg-purple-500 !border-2 !border-white"
        style={{ left: '33%' }}
      />
      <Handle
        type="source"
        position={Position.Right}
        id="loop"
        className="w-3 h-3 !bg-purple-500 !border-2 !border-white"
      />
    </div>
  );
});
