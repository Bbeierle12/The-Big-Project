import React, { useState, RefObject } from 'react';
import { Node, Connection } from '../types';

interface InteractionProps {
  svgRef: RefObject<SVGSVGElement | null>;
  nodes: Node[];
  setNodes: React.Dispatch<React.SetStateAction<Node[]>>;
  connections: Connection[];
  setConnections: React.Dispatch<React.SetStateAction<Connection[]>>;
  selectedIds: string[];
  setSelectedIds: React.Dispatch<React.SetStateAction<string[]>>;
}

export const useInteraction = ({
  svgRef,
  nodes,
  setNodes,
  connections,
  setConnections,
  selectedIds,
  setSelectedIds
}: InteractionProps) => {
  const [mode, setMode] = useState<'select' | 'connect'>('select');
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [isDraggingNodes, setIsDraggingNodes] = useState(false);
  const [selectionBox, setSelectionBox] = useState<{start: {x: number, y: number}, current: {x: number, y: number}} | null>(null);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 }); 
  const [nodeDragOffsets, setNodeDragOffsets] = useState<Record<string, {x: number, y: number}>>({});
  const [connectingFrom, setConnectingFrom] = useState<string | null>(null);

  const getCoords = (e: React.MouseEvent) => {
    if (svgRef.current) {
      const CTM = svgRef.current.getScreenCTM();
      if (CTM) {
        return {
          x: (e.clientX - CTM.e) / CTM.a,
          y: (e.clientY - CTM.f) / CTM.d
        };
      }
    }
    return { x: 0, y: 0 };
  };

  const handleMouseDown = (e: React.MouseEvent) => {
    const coords = getCoords(e);
    
    if (e.button === 0 && !e.shiftKey) {
       setSelectionBox({ start: coords, current: coords });
       setSelectedIds([]);
    } else {
       setIsPanning(true);
       setDragStart(coords);
    }
    setConnectingFrom(null);
  };

  const handleNodeDown = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    
    if (mode === 'connect') {
      if (connectingFrom === null) {
        setConnectingFrom(id);
      } else {
        if (connectingFrom === id) {
          setConnectingFrom(null);
          setMode('select');
          return;
        }

        const connectionExists = connections.some(c => 
          (c.from === connectingFrom && c.to === id) || 
          (c.from === id && c.to === connectingFrom)
        );

        if (connectionExists) {
          alert("Connection already exists between these nodes.");
          setConnectingFrom(null);
          setMode('select');
          return;
        }

        setConnections(prev => [...prev, { 
          id: `c-${Date.now()}`, 
          from: connectingFrom, 
          to: id, 
          traffic: 5, 
          type: 'wired',
          speed: '1 Gbps'
        }]);
        
        setConnectingFrom(null);
        setMode('select');
      }
      return;
    }

    let newSelected = [...selectedIds];
    if (e.shiftKey) {
      if (newSelected.includes(id)) {
        newSelected = newSelected.filter(sid => sid !== id);
      } else {
        newSelected.push(id);
      }
    } else {
      if (!newSelected.includes(id)) {
        newSelected = [id];
      }
    }
    setSelectedIds(newSelected);

    setIsDraggingNodes(true);
    const coords = getCoords(e);
    setDragStart(coords);

    const offsets: Record<string, {x: number, y: number}> = {};
    const nodesToMove = new Set<string>(newSelected);
    
    nodes.forEach(n => {
       if (n.parentId && newSelected.includes(n.parentId)) {
         nodesToMove.add(n.id);
       }
    });

    nodes.forEach(n => {
      if (nodesToMove.has(n.id)) {
        offsets[n.id] = { x: n.x, y: n.y };
      }
    });
    setNodeDragOffsets(offsets);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const coords = getCoords(e);

    if (isPanning) {
      setPan(prev => ({ 
        x: prev.x + (e.movementX), 
        y: prev.y + (e.movementY) 
      }));
    }

    if (isDraggingNodes) {
      const dx = coords.x - dragStart.x;
      const dy = coords.y - dragStart.y;
      
      setNodes(prev => prev.map(n => {
        if (nodeDragOffsets[n.id]) {
          return {
            ...n,
            x: nodeDragOffsets[n.id].x + dx,
            y: nodeDragOffsets[n.id].y + dy
          };
        }
        return n;
      }));
    }

    if (selectionBox) {
      setSelectionBox({ ...selectionBox, current: coords });
    }
  };

  const handleMouseUp = () => {
    if (selectionBox) {
      const { start, current } = selectionBox;
      const x1 = Math.min(start.x, current.x) - pan.x;
      const x2 = Math.max(start.x, current.x) - pan.x;
      const y1 = Math.min(start.y, current.y) - pan.y;
      const y2 = Math.max(start.y, current.y) - pan.y;

      const intersectingNodes = nodes.filter(n => 
        n.x >= x1 && n.x <= x2 && n.y >= y1 && n.y <= y2
      ).map(n => n.id);
      
      setSelectedIds(intersectingNodes);
      setSelectionBox(null);
    }
    setIsPanning(false);
    setIsDraggingNodes(false);
    setNodeDragOffsets({});
  };

  return {
    mode,
    setMode,
    pan,
    isPanning,
    selectionBox,
    handleMouseDown,
    handleMouseMove,
    handleMouseUp,
    handleNodeDown
  };
};