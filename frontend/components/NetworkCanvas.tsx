import React, { forwardRef } from 'react';
import { Node, Connection } from '../types';
import { NetworkNode } from './NetworkNode';
import { NetworkConnection } from './NetworkConnection';

interface NetworkCanvasProps {
  nodes: Node[];
  connections: Connection[];
  pan: { x: number; y: number };
  isPanning: boolean;
  selectedIds: string[];
  selectionBox: { start: { x: number; y: number }; current: { x: number; y: number } } | null;
  hoveredConnection: string | null;
  setHoveredConnection: (id: string | null) => void;
  onMouseDown: (e: React.MouseEvent) => void;
  onMouseMove: (e: React.MouseEvent) => void;
  onMouseUp: (e: React.MouseEvent) => void;
  onNodeDown: (e: React.MouseEvent, id: string) => void;
}

export const NetworkCanvas = forwardRef<SVGSVGElement, NetworkCanvasProps>(({
  nodes, connections, pan, isPanning, selectedIds, selectionBox,
  hoveredConnection, setHoveredConnection,
  onMouseDown, onMouseMove, onMouseUp, onNodeDown
}, ref) => {
  return (
    <svg 
      ref={ref}
      className={`h-full w-full touch-none ${isPanning ? 'cursor-grabbing' : 'cursor-grab'}`}
      onMouseDown={onMouseDown}
      onMouseMove={onMouseMove}
      onMouseUp={onMouseUp}
      onMouseLeave={onMouseUp}
    >
      <g transform={`translate(${pan.x}, ${pan.y})`}>
        {/* Selection Box */}
        {selectionBox && (
          <rect 
             x={Math.min(selectionBox.start.x, selectionBox.current.x) - pan.x}
             y={Math.min(selectionBox.start.y, selectionBox.current.y) - pan.y}
             width={Math.abs(selectionBox.current.x - selectionBox.start.x)}
             height={Math.abs(selectionBox.current.y - selectionBox.start.y)}
             fill="rgba(6,182,212,0.1)"
             stroke="#06b6d4"
             strokeWidth="1"
             strokeDasharray="4 4"
             pointerEvents="none"
          />
        )}

        {/* Connections */}
        {connections.map(conn => (
          <NetworkConnection 
            key={conn.id} 
            connection={conn} 
            nodes={nodes} 
            hoveredConnection={hoveredConnection}
            setHoveredConnection={setHoveredConnection}
          />
        ))}

        {/* Groups (Render First) */}
        {nodes.filter(n => n.type === 'group').map(node => (
          <NetworkNode 
            key={node.id} 
            node={node} 
            isSelected={selectedIds.includes(node.id)}
            onMouseDown={onNodeDown}
          />
        ))}

        {/* Standard Nodes */}
        {nodes.filter(n => n.type !== 'group').map(node => (
          <NetworkNode 
            key={node.id} 
            node={node} 
            isSelected={selectedIds.includes(node.id)}
            onMouseDown={onNodeDown}
          />
        ))}
      </g>
    </svg>
  );
});
