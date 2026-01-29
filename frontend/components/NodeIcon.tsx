import React from 'react';
import { 
  Server, Shield, Router, Wifi, Database, Laptop, 
  Smartphone, Globe, Cpu, Activity, Layers 
} from 'lucide-react';
import { NodeType } from '../types';

interface NodeIconProps {
  type: NodeType;
  size?: number;
  className?: string;
  style?: React.CSSProperties;
}

export const NodeIcon: React.FC<NodeIconProps> = ({ type, size = 24, className = "", style = {} }) => {
  switch (type) {
    case 'server': return <Server size={size} className={className} style={style} />;
    case 'firewall': return <Shield size={size} className={className} style={style} />;
    case 'router': return <Router size={size} className={className} style={style} />;
    case 'extender': return <Wifi size={size} className={className} style={style} />;
    case 'database': return <Database size={size} className={className} style={style} />;
    case 'workstation': return <Laptop size={size} className={className} style={style} />;
    case 'mobile': return <Smartphone size={size} className={className} style={style} />;
    case 'cloud': return <Globe size={size} className={className} style={style} />;
    case 'iot': return <Cpu size={size} className={className} style={style} />;
    case 'group': return <Layers size={size} className={className} style={style} />;
    default: return <Activity size={size} className={className} style={style} />;
  }
};