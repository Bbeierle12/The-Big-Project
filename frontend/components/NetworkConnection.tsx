import React from 'react';
import { Connection, Node } from '../types';

interface NetworkConnectionProps {
  connection: Connection;
  nodes: Node[];
  hoveredConnection: string | null;
  setHoveredConnection: (id: string | null) => void;
}

export const NetworkConnection: React.FC<NetworkConnectionProps> = ({ 
  connection, nodes, hoveredConnection, setHoveredConnection 
}) => {
  const from = nodes.find(n => n.id === connection.from);
  const to = nodes.find(n => n.id === connection.to);
  if (!from || !to) return null;

  const isWireless = connection.type === 'wireless';
  const isHovered = hoveredConnection === connection.id;

  const getCenter = (n: Node) => {
    if (n.type === 'group') {
      return { x: n.x + (n.width || 0)/2, y: n.y + (n.height || 0)/2 };
    }
    return { x: n.x, y: n.y };
  }

  const start = getCenter(from);
  const end = getCenter(to);
  const midX = (start.x + end.x) / 2;
  const midY = (start.y + end.y) / 2;

  return (
    <g 
      className="transition-all duration-300"
      onMouseEnter={() => setHoveredConnection(connection.id)}
      onMouseLeave={() => setHoveredConnection(null)}
    >
      {isHovered && (
         <line 
           x1={start.x} y1={start.y} x2={end.x} y2={end.y} 
           stroke="#22d3ee" 
           strokeWidth={isWireless ? 4 : 6}
           opacity="0.5"
           className="animate-pulse"
         />
      )}
      <line 
        x1={start.x} y1={start.y} x2={end.x} y2={end.y} 
        stroke={isHovered ? '#22d3ee' : (isWireless ? '#334155' : '#1e293b')} 
        strokeWidth={isWireless ? 1 : 2} 
      />
      <line 
        x1={start.x} y1={start.y} x2={end.x} y2={end.y} 
        stroke={isHovered ? '#06b6d4' : (isWireless ? '#0ea5e9' : '#06b6d4')} 
        strokeWidth="1"
        strokeDasharray="4,4"
        className="animate-dash"
        opacity={isWireless ? "0.3" : "0.6"}
      />
      
      <g transform={`translate(${midX}, ${midY})`}>
        {isWireless && connection.ssid && (
          <g transform={connection.speed ? "translate(0, -9)" : ""}>
            <rect x="-40" y="-7" width="80" height="14" rx="2" fill="#0c0c0c" stroke="#1e293b" strokeWidth="1" />
            <text y="2.5" fill="#0ea5e9" fontSize="7" textAnchor="middle" className="font-bold tracking-tighter uppercase pointer-events-none">
               {connection.ssid}
            </text>
          </g>
        )}

        {connection.speed && (
           <g transform={isWireless && connection.ssid ? "translate(0, 9)" : ""}>
             <rect x="-24" y="-6" width="48" height="12" rx="2" fill="#000" stroke={isWireless ? "#334155" : "#0891b2"} strokeWidth="1" />
             <text y="2.5" fill={isWireless ? "#94a3b8" : "#67e8f9"} fontSize="6" textAnchor="middle" className="font-mono font-bold tracking-wider pointer-events-none">
                {connection.speed}
             </text>
           </g>
        )}
      </g>
    </g>
  );
};