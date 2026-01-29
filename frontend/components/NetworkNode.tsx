import React from 'react';
import { Layers, AlertTriangle, Skull } from 'lucide-react';
import { NodeIcon } from './NodeIcon';
import { Node, NodeType } from '../types';

interface NetworkNodeProps {
  node: Node;
  isSelected: boolean;
  onMouseDown: (e: React.MouseEvent, id: string) => void;
}

export const NetworkNode: React.FC<NetworkNodeProps> = ({ node, isSelected, onMouseDown }) => {
  const getNodeColor = (type: NodeType) => {
    switch(type) {
      case 'firewall': return '#f43f5e'; 
      case 'router': return '#f59e0b'; 
      case 'database': return '#a855f7'; 
      case 'cloud': return '#3b82f6'; 
      case 'iot': return '#10b981';
      case 'extender': return '#0ea5e9';
      case 'group': return '#64748b';
      default: return '#06b6d4'; 
    }
  };

  const getStatusColor = (status: Node['status']) => {
    switch(status) {
      case 'compromised': return '#ef4444'; // Red-500
      case 'warning': return '#f59e0b'; // Amber-500
      case 'offline': return '#64748b'; // Slate-500
      default: return getNodeColor(node.type);
    }
  };

  const color = getStatusColor(node.status);
  const isCompromised = node.status === 'compromised';

  if (node.type === 'group') {
    return (
      <g 
        transform={`translate(${node.x}, ${node.y})`}
        onMouseDown={(e) => onMouseDown(e, node.id)}
        className="cursor-move"
      >
        <rect 
          width={node.width || 200} 
          height={node.height || 200}
          fill={isSelected ? 'rgba(30, 41, 59, 0.4)' : 'rgba(30, 41, 59, 0.1)'}
          stroke={isSelected ? '#94a3b8' : '#334155'}
          strokeWidth="1"
          strokeDasharray="8 4"
          rx="4"
        />
        <foreignObject x="0" y="-24" width={node.width || 200} height="20">
           <div className="flex items-center gap-2 px-2">
             <Layers size={12} className="text-slate-500" />
             <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{node.label}</span>
           </div>
        </foreignObject>
      </g>
    );
  }

  const isAP = node.ssids && node.ssids.length > 0;

  return (
    <g 
      transform={`translate(${node.x}, ${node.y})`}
      onMouseDown={(e) => onMouseDown(e, node.id)}
      className="cursor-pointer"
    >
       {/* Wireless Pulse */}
       {isAP && !isCompromised && (
         <circle r="160" fill="none" stroke={color} strokeWidth="0.5" opacity="0.1" strokeDasharray="10,10" className="animate-spin-slow" />
       )}

       {/* Selection Indicators */}
       {isSelected && (
         <>
           <circle r="32" fill="none" stroke={color} strokeWidth="1" strokeDasharray="4 2" className="animate-spin-slow" />
           <circle r="32" fill="none" stroke={color} strokeWidth="2" className="animate-pulse-ring" />
         </>
       )}

       {/* Compromised Effect */}
       {isCompromised && (
         <>
           <circle r="28" fill="none" stroke="#ef4444" strokeWidth="2" opacity="0.6" className="animate-ping" />
           <circle r="35" fill="none" stroke="#ef4444" strokeWidth="0.5" strokeDasharray="2 2" className="animate-spin" />
         </>
       )}

       {/* Main Node Body */}
       <circle r="20" fill="#000" stroke={isSelected || isCompromised ? color : '#1e293b'} strokeWidth="2" />
       
       {/* Icon */}
       <foreignObject x="-10" y="-10" width="20" height="20" className="pointer-events-none">
         <div className="flex items-center justify-center h-full w-full">
           {isCompromised ? (
             <Skull size={16} className="text-red-500 animate-pulse" />
           ) : node.status === 'warning' ? (
             <AlertTriangle size={16} className="text-amber-500" />
           ) : (
             <NodeIcon type={node.type} size={16} style={{ color: isSelected ? '#ffffff' : color }} />
           )}
         </div>
       </foreignObject>

       {/* Label */}
       <text y="36" fill={isCompromised ? '#ef4444' : (isSelected ? '#fff' : '#64748b')} fontSize="10" textAnchor="middle" className="font-bold select-none uppercase tracking-tighter">
         {node.label}
       </text>
       
       {/* Status Label */}
       {isCompromised && (
         <text y="-35" fill="#ef4444" fontSize="8" textAnchor="middle" className="font-black tracking-widest uppercase animate-pulse">
            PWNED
         </text>
       )}

       {node.vendor && isSelected && !isCompromised && (
         <text y="-35" fill={color} fontSize="8" textAnchor="middle" className="font-black tracking-widest uppercase opacity-80">
            {node.vendor}
         </text>
       )}
    </g>
  );
};