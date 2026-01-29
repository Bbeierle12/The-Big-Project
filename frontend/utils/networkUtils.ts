import { NodeType } from '../types';

export const lookupOUI = (vendorString: string): string => {
  const ouiDatabase: Record<string, string> = {
    'Juniper Networks': '00:10:DB',
    'ASUS (RT-AX88U)': '04:D4:C4',
    'TP-Link': '18:D6:C7',
    'Signify N.V.': '00:17:88',
    'Apple Inc.': 'AC:3C:0B',
    'Samsung': '24:F5:AA',
    'Dell Technologies': '54:BF:64',
    'August Home': 'D8:28:C9',
    'Ubiquiti (UniFi)': '74:83:C2',
    'Generic Hardware': 'E0:D5:5E',
    'Sony Corporation': 'F0:BF:97',
    'Amazon Technologies': '74:C2:46',
    'Google': '3C:5A:B4',
    'Nest Labs': '18:B4:30',
    'Microsoft Corporation': '00:12:5A',
    'Intel Corporate': '00:1B:21',
    'Cisco Systems': '00:01:42'
  };

  return ouiDatabase[vendorString] || 'XX:XX:XX';
};

export const isValidCIDR = (cidr: string): boolean => {
  const cidrRegex = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
  if (!cidrRegex.test(cidr)) return false;
  
  const [ip] = cidr.split('/');
  return ip.split('.').every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
};

export const randomIP = () => `192.168.1.${Math.floor(Math.random() * 254) + 10}`;

export const HARDWARE_POOL: {type: NodeType, label: string, vendor: string}[] = [
  { type: 'iot', label: 'Philips Hue Hub', vendor: 'Signify N.V.' },
  { type: 'mobile', label: 'iPad Air', vendor: 'Apple Inc.' },
  { type: 'mobile', label: 'Galaxy S24', vendor: 'Samsung' },
  { type: 'workstation', label: 'Design-Workstation', vendor: 'Dell Technologies' },
  { type: 'iot', label: 'Smart Lock', vendor: 'August Home' },
  { type: 'router', label: 'Sub-Gateway', vendor: 'Ubiquiti (UniFi)' },
  { type: 'iot', label: 'Kitchen Fridge', vendor: 'Samsung' },
  { type: 'iot', label: 'Echo Dot', vendor: 'Amazon Technologies' },
  { type: 'iot', label: 'Nest Thermostat', vendor: 'Nest Labs' },
  { type: 'workstation', label: 'Surface Studio', vendor: 'Microsoft Corporation' },
  { type: 'iot', label: 'Bravia Smart TV', vendor: 'Sony Corporation' }
];
