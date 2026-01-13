import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Box,
  Paper,
  IconButton,
  Tooltip,
  Divider,
  ToggleButton,
  ToggleButtonGroup,
  Slider,
  Popover,
  Typography,
  TextField,
  Avatar,
  AvatarGroup,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Snackbar,
  Alert,
  Drawer,
} from '@mui/material';
// Using MUI icons instead of lucide-react
import MouseIcon from '@mui/icons-material/Mouse';
import CropSquareIcon from '@mui/icons-material/CropSquare';
import CircleOutlinedIcon from '@mui/icons-material/CircleOutlined';
import TextFieldsIcon from '@mui/icons-material/TextFields';
import RemoveIcon from '@mui/icons-material/Remove';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CreateIcon from '@mui/icons-material/Create';
import AutoFixOffIcon from '@mui/icons-material/AutoFixOff';
import ImageIcon from '@mui/icons-material/Image';
import StickyNote2Icon from '@mui/icons-material/StickyNote2';
import PanToolIcon from '@mui/icons-material/PanTool';
import ZoomInIcon from '@mui/icons-material/ZoomIn';
import ZoomOutIcon from '@mui/icons-material/ZoomOut';
import UndoIcon from '@mui/icons-material/Undo';
import RedoIcon from '@mui/icons-material/Redo';
import DeleteIcon from '@mui/icons-material/Delete';
import DownloadIcon from '@mui/icons-material/Download';
import UploadIcon from '@mui/icons-material/Upload';
import GroupIcon from '@mui/icons-material/Group';
import PaletteIcon from '@mui/icons-material/Palette';
import SettingsIcon from '@mui/icons-material/Settings';
import GridOnIcon from '@mui/icons-material/GridOn';
import GridOffIcon from '@mui/icons-material/GridOff';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import SaveIcon from '@mui/icons-material/Save';
import ChevronLeftIcon from '@mui/icons-material/ChevronLeft';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';
import FormatSizeIcon from '@mui/icons-material/FormatSize';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ContentPasteIcon from '@mui/icons-material/ContentPaste';
import FlipToFrontIcon from '@mui/icons-material/FlipToFront';
import FlipToBackIcon from '@mui/icons-material/FlipToBack';
import OpacityIcon from '@mui/icons-material/Opacity';
import AddPhotoAlternateIcon from '@mui/icons-material/AddPhotoAlternate';
import FitScreenIcon from '@mui/icons-material/FitScreen';
import SelectAllIcon from '@mui/icons-material/SelectAll';
import ContentCutIcon from '@mui/icons-material/ContentCut';
import VerticalAlignTopIcon from '@mui/icons-material/VerticalAlignTop';
import VerticalAlignCenterIcon from '@mui/icons-material/VerticalAlignCenter';
import VerticalAlignBottomIcon from '@mui/icons-material/VerticalAlignBottom';
import AlignHorizontalLeftIcon from '@mui/icons-material/AlignHorizontalLeft';
import AlignHorizontalCenterIcon from '@mui/icons-material/AlignHorizontalCenter';
import AlignHorizontalRightIcon from '@mui/icons-material/AlignHorizontalRight';
import FullscreenIcon from '@mui/icons-material/Fullscreen';
import FullscreenExitIcon from '@mui/icons-material/FullscreenExit';
import CloseIcon from '@mui/icons-material/Close';
import RouterIcon from '@mui/icons-material/Router';
import StorageIcon from '@mui/icons-material/Storage';
import ComputerIcon from '@mui/icons-material/Computer';
import CloudIcon from '@mui/icons-material/Cloud';
import SecurityIcon from '@mui/icons-material/Security';
import WifiIcon from '@mui/icons-material/Wifi';
import DevicesIcon from '@mui/icons-material/Devices';
import LaptopIcon from '@mui/icons-material/Laptop';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import PrintIcon from '@mui/icons-material/Print';
import PublicIcon from '@mui/icons-material/Public';
import HubIcon from '@mui/icons-material/Hub';
import DnsIcon from '@mui/icons-material/Dns';
import CategoryIcon from '@mui/icons-material/Category';
import PhoneIphoneIcon from '@mui/icons-material/PhoneIphone';
import AppleIcon from '@mui/icons-material/Apple';
import AndroidIcon from '@mui/icons-material/Android';
import JavascriptIcon from '@mui/icons-material/Javascript';
import CodeIcon from '@mui/icons-material/Code';
import TerminalIcon from '@mui/icons-material/Terminal';
import DataObjectIcon from '@mui/icons-material/DataObject';
import TableChartIcon from '@mui/icons-material/TableChart';
import ApiIcon from '@mui/icons-material/Api';
import WebIcon from '@mui/icons-material/Web';
import HttpIcon from '@mui/icons-material/Http';
import FolderIcon from '@mui/icons-material/Folder';
import MemoryIcon from '@mui/icons-material/Memory';
import DeveloperBoardIcon from '@mui/icons-material/DeveloperBoard';
import SmartphoneIcon from '@mui/icons-material/Smartphone';
import TabletIcon from '@mui/icons-material/Tablet';
import WatchIcon from '@mui/icons-material/Watch';
import TvIcon from '@mui/icons-material/Tv';
import SpeakerIcon from '@mui/icons-material/Speaker';
import KeyboardIcon from '@mui/icons-material/Keyboard';
import MouseOutlinedIcon from '@mui/icons-material/MouseOutlined';
import UsbIcon from '@mui/icons-material/Usb';
import BluetoothIcon from '@mui/icons-material/Bluetooth';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import BugReportIcon from '@mui/icons-material/BugReport';
import BuildIcon from '@mui/icons-material/Build';
import IntegrationInstructionsIcon from '@mui/icons-material/IntegrationInstructions';
import SignalCellularAltIcon from '@mui/icons-material/SignalCellularAlt';
import SignalWifi4BarIcon from '@mui/icons-material/SignalWifi4Bar';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import NetworkCellIcon from '@mui/icons-material/NetworkCell';
import FourGMobiledataIcon from '@mui/icons-material/FourGMobiledata';
import FiveGIcon from '@mui/icons-material/FiveG';
import CloudQueueIcon from '@mui/icons-material/CloudQueue';
import SatelliteAltIcon from '@mui/icons-material/SatelliteAlt';
import CableIcon from '@mui/icons-material/Cable';
import GpsFixedIcon from '@mui/icons-material/GpsFixed';
import RadarIcon from '@mui/icons-material/Radar';
import AnalyticsIcon from '@mui/icons-material/Analytics';
import DataUsageIcon from '@mui/icons-material/DataUsage';
import SpeedIcon from '@mui/icons-material/Speed';
import ElectricBoltIcon from '@mui/icons-material/ElectricBolt';
import TokenIcon from '@mui/icons-material/Token';
import HexagonIcon from '@mui/icons-material/Hexagon';
import ViewInArIcon from '@mui/icons-material/ViewInAr';
import SmartToyIcon from '@mui/icons-material/SmartToy';
import PsychologyIcon from '@mui/icons-material/Psychology';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import ChangeHistoryIcon from '@mui/icons-material/ChangeHistory';
import DiamondIcon from '@mui/icons-material/Diamond';
import StarIcon from '@mui/icons-material/Star';
import SyncAltIcon from '@mui/icons-material/SyncAlt';
import TimerIcon from '@mui/icons-material/Timer';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PauseIcon from '@mui/icons-material/Pause';
import ReplayIcon from '@mui/icons-material/Replay';
import TableChartOutlinedIcon from '@mui/icons-material/TableChartOutlined';
import DashboardCustomizeIcon from '@mui/icons-material/DashboardCustomize';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import LinkIcon from '@mui/icons-material/Link';
import ThumbUpIcon from '@mui/icons-material/ThumbUp';
import FlagIcon from '@mui/icons-material/Flag';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import WarningIcon from '@mui/icons-material/Warning';
import BlockIcon from '@mui/icons-material/Block';
import SearchIcon from '@mui/icons-material/Search';
import FormatBoldIcon from '@mui/icons-material/FormatBold';
import FormatItalicIcon from '@mui/icons-material/FormatItalic';
import FormatUnderlinedIcon from '@mui/icons-material/FormatUnderlined';
import FormatListBulletedIcon from '@mui/icons-material/FormatListBulleted';
import ChecklistIcon from '@mui/icons-material/Checklist';
import GradientIcon from '@mui/icons-material/Gradient';
import FontDownloadIcon from '@mui/icons-material/FontDownload';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import SummarizeIcon from '@mui/icons-material/Summarize';
import CategoryOutlinedIcon from '@mui/icons-material/CategoryOutlined';
import CheckBoxIcon from '@mui/icons-material/CheckBox';
import CheckBoxOutlineBlankIcon from '@mui/icons-material/CheckBoxOutlineBlank';
import LinkOffIcon from '@mui/icons-material/LinkOff';
import LaunchIcon from '@mui/icons-material/Launch';
import CommentIcon from '@mui/icons-material/Comment';
import GroupWorkIcon from '@mui/icons-material/GroupWork';
import GroupsIcon from '@mui/icons-material/Groups';
import AlternateEmailIcon from '@mui/icons-material/AlternateEmail';
import AutoFixNormalIcon from '@mui/icons-material/AutoFixNormal';
import ViewModuleIcon from '@mui/icons-material/ViewModule';
import GridViewIcon from '@mui/icons-material/GridView';
import PhotoSizeSelectSmallIcon from '@mui/icons-material/PhotoSizeSelectSmall';
import PhotoSizeSelectLargeIcon from '@mui/icons-material/PhotoSizeSelectLarge';
import AspectRatioIcon from '@mui/icons-material/AspectRatio';
import SendIcon from '@mui/icons-material/Send';
import PersonIcon from '@mui/icons-material/Person';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import { whiteboardClient, WhiteboardElement as ClientWhiteboardElement } from '../api/client';
import { useAuth } from '../contexts/AuthContext';
import { aiClient } from '../api/client';

// Sticky note color presets
const STICKY_COLORS = [
  { name: 'Yellow', color: '#fef08a', textColor: '#000000' },
  { name: 'Pink', color: '#fda4af', textColor: '#000000' },
  { name: 'Blue', color: '#93c5fd', textColor: '#000000' },
  { name: 'Green', color: '#86efac', textColor: '#000000' },
  { name: 'Orange', color: '#fdba74', textColor: '#000000' },
  { name: 'Purple', color: '#c4b5fd', textColor: '#000000' },
  { name: 'Cyan', color: '#67e8f9', textColor: '#000000' },
  { name: 'Lime', color: '#bef264', textColor: '#000000' },
];

// Gradient presets
const GRADIENT_PRESETS = [
  { name: 'Sunset', start: '#f97316', end: '#ec4899' },
  { name: 'Ocean', start: '#06b6d4', end: '#3b82f6' },
  { name: 'Forest', start: '#22c55e', end: '#14b8a6' },
  { name: 'Purple Haze', start: '#8b5cf6', end: '#ec4899' },
  { name: 'Fire', start: '#ef4444', end: '#f59e0b' },
  { name: 'Night', start: '#1e1e2e', end: '#3b82f6' },
  { name: 'Gold', start: '#f59e0b', end: '#eab308' },
  { name: 'Ice', start: '#e0f2fe', end: '#7dd3fc' },
];

// Font options
const FONT_OPTIONS = [
  { name: 'Inter', value: 'Inter, sans-serif' },
  { name: 'Roboto', value: 'Roboto, sans-serif' },
  { name: 'Open Sans', value: '"Open Sans", sans-serif' },
  { name: 'Poppins', value: 'Poppins, sans-serif' },
  { name: 'Montserrat', value: 'Montserrat, sans-serif' },
  { name: 'Courier', value: '"Courier New", monospace' },
  { name: 'Georgia', value: 'Georgia, serif' },
  { name: 'Comic Sans', value: '"Comic Sans MS", cursive' },
];

// Network Symbol Definitions
interface NetworkSymbol {
  id: string;
  name: string;
  icon: string; // SVG path or identifier
  category: 'network' | 'server' | 'endpoint' | 'security' | 'cloud' | 'framework' | 'database' | 'mobile' | 'hardware' | 'ai';
}

const NETWORK_SYMBOLS: NetworkSymbol[] = [
  // Network devices
  { id: 'router', name: 'Router', icon: 'router', category: 'network' },
  { id: 'switch', name: 'Switch', icon: 'switch', category: 'network' },
  { id: 'hub', name: 'Hub', icon: 'hub', category: 'network' },
  { id: 'wireless_ap', name: 'Wireless AP', icon: 'wireless', category: 'network' },
  { id: 'vpn', name: 'VPN', icon: 'vpn', category: 'network' },
  { id: 'loadbalancer', name: 'Load Balancer', icon: 'loadbalancer', category: 'network' },
  // Security
  { id: 'firewall', name: 'Firewall', icon: 'firewall', category: 'security' },
  { id: 'lock', name: 'Lock/Encryption', icon: 'lock', category: 'security' },
  { id: 'key', name: 'Key/Auth', icon: 'key', category: 'security' },
  { id: 'bug', name: 'Bug/Vulnerability', icon: 'bug', category: 'security' },
  // Servers & Backend
  { id: 'server', name: 'Server', icon: 'server', category: 'server' },
  { id: 'web_server', name: 'Web Server', icon: 'webserver', category: 'server' },
  { id: 'api', name: 'API Server', icon: 'api', category: 'server' },
  { id: 'nodejs', name: 'Node.js', icon: 'nodejs', category: 'server' },
  { id: 'php', name: 'PHP', icon: 'php', category: 'server' },
  { id: 'python', name: 'Python', icon: 'python', category: 'server' },
  { id: 'java', name: 'Java', icon: 'java', category: 'server' },
  { id: 'docker', name: 'Docker', icon: 'docker', category: 'server' },
  { id: 'kubernetes', name: 'Kubernetes', icon: 'kubernetes', category: 'server' },
  // Databases
  { id: 'database', name: 'Database', icon: 'database', category: 'database' },
  { id: 'mysql', name: 'MySQL', icon: 'mysql', category: 'database' },
  { id: 'postgresql', name: 'PostgreSQL', icon: 'postgresql', category: 'database' },
  { id: 'mongodb', name: 'MongoDB', icon: 'mongodb', category: 'database' },
  { id: 'redis', name: 'Redis', icon: 'redis', category: 'database' },
  { id: 'sql', name: 'SQL', icon: 'sql', category: 'database' },
  // Frontend Frameworks
  { id: 'react', name: 'React', icon: 'react', category: 'framework' },
  { id: 'vue', name: 'Vue.js', icon: 'vue', category: 'framework' },
  { id: 'angular', name: 'Angular', icon: 'angular', category: 'framework' },
  { id: 'vite', name: 'Vite', icon: 'vite', category: 'framework' },
  { id: 'nextjs', name: 'Next.js', icon: 'nextjs', category: 'framework' },
  { id: 'typescript', name: 'TypeScript', icon: 'typescript', category: 'framework' },
  { id: 'javascript', name: 'JavaScript', icon: 'javascript', category: 'framework' },
  { id: 'html', name: 'HTML', icon: 'html', category: 'framework' },
  { id: 'css', name: 'CSS', icon: 'css', category: 'framework' },
  // Mobile & Devices
  { id: 'iphone', name: 'iPhone', icon: 'iphone', category: 'mobile' },
  { id: 'ios', name: 'iOS/Apple', icon: 'ios', category: 'mobile' },
  { id: 'android', name: 'Android', icon: 'android', category: 'mobile' },
  { id: 'tablet', name: 'Tablet/iPad', icon: 'tablet', category: 'mobile' },
  { id: 'smartwatch', name: 'Smart Watch', icon: 'smartwatch', category: 'mobile' },
  // Endpoints
  { id: 'pc', name: 'PC/Desktop', icon: 'pc', category: 'endpoint' },
  { id: 'laptop', name: 'Laptop', icon: 'laptop', category: 'endpoint' },
  { id: 'mobile', name: 'Mobile Device', icon: 'mobile', category: 'endpoint' },
  { id: 'printer', name: 'Printer', icon: 'printer', category: 'endpoint' },
  { id: 'tv', name: 'TV/Display', icon: 'tv', category: 'endpoint' },
  { id: 'speaker', name: 'Smart Speaker', icon: 'speaker', category: 'endpoint' },
  // Hardware
  { id: 'cpu', name: 'CPU/Processor', icon: 'cpu', category: 'hardware' },
  { id: 'memory', name: 'Memory/RAM', icon: 'memory', category: 'hardware' },
  { id: 'usb', name: 'USB Device', icon: 'usb', category: 'hardware' },
  { id: 'bluetooth', name: 'Bluetooth', icon: 'bluetooth', category: 'hardware' },
  { id: 'keyboard', name: 'Keyboard', icon: 'keyboard', category: 'hardware' },
  { id: 'mouse', name: 'Mouse', icon: 'mouse', category: 'hardware' },
  // Cloud/Internet
  { id: 'cloud', name: 'Cloud', icon: 'cloud', category: 'cloud' },
  { id: 'internet', name: 'Internet', icon: 'internet', category: 'cloud' },
  { id: 'aws', name: 'AWS', icon: 'aws', category: 'cloud' },
  { id: 'azure', name: 'Azure', icon: 'azure', category: 'cloud' },
  { id: 'gcp', name: 'Google Cloud', icon: 'gcp', category: 'cloud' },
  { id: 'alibaba', name: 'Alibaba Cloud', icon: 'alibaba', category: 'cloud' },
  { id: 'huawei', name: 'Huawei Cloud', icon: 'huawei', category: 'cloud' },
  { id: 'yandex', name: 'Yandex Cloud', icon: 'yandex', category: 'cloud' },
  { id: 'oracle', name: 'Oracle Cloud', icon: 'oracle', category: 'cloud' },
  { id: 'ibm', name: 'IBM Cloud', icon: 'ibm', category: 'cloud' },
  { id: 'digitalocean', name: 'DigitalOcean', icon: 'digitalocean', category: 'cloud' },
  // Connectivity
  { id: 'cellular', name: 'Cellular Signal', icon: 'cellular', category: 'network' },
  { id: 'wifi_signal', name: 'WiFi Signal', icon: 'wifi_signal', category: 'network' },
  { id: 'wifi_off', name: 'WiFi Off', icon: 'wifi_off', category: 'network' },
  { id: '4g', name: '4G LTE', icon: '4g', category: 'network' },
  { id: '5g', name: '5G', icon: '5g', category: 'network' },
  { id: 'satellite', name: 'Satellite', icon: 'satellite', category: 'network' },
  { id: 'ethernet', name: 'Ethernet Cable', icon: 'ethernet', category: 'network' },
  { id: 'gps', name: 'GPS', icon: 'gps', category: 'network' },
  // More Languages
  { id: 'go', name: 'Go/Golang', icon: 'go', category: 'framework' },
  { id: 'rust', name: 'Rust', icon: 'rust', category: 'framework' },
  { id: 'csharp', name: 'C#', icon: 'csharp', category: 'framework' },
  { id: 'cpp', name: 'C++', icon: 'cpp', category: 'framework' },
  { id: 'ruby', name: 'Ruby', icon: 'ruby', category: 'framework' },
  { id: 'swift', name: 'Swift', icon: 'swift', category: 'framework' },
  { id: 'kotlin', name: 'Kotlin', icon: 'kotlin', category: 'framework' },
  { id: 'flutter', name: 'Flutter', icon: 'flutter', category: 'framework' },
  { id: 'svelte', name: 'Svelte', icon: 'svelte', category: 'framework' },
  { id: 'graphql', name: 'GraphQL', icon: 'graphql', category: 'framework' },
  { id: 'linux', name: 'Linux', icon: 'linux', category: 'server' },
  { id: 'windows_server', name: 'Windows Server', icon: 'windows_server', category: 'server' },
  { id: 'nginx', name: 'Nginx', icon: 'nginx', category: 'server' },
  { id: 'apache', name: 'Apache', icon: 'apache', category: 'server' },
  // More Databases
  { id: 'elasticsearch', name: 'Elasticsearch', icon: 'elasticsearch', category: 'database' },
  { id: 'cassandra', name: 'Cassandra', icon: 'cassandra', category: 'database' },
  { id: 'sqlite', name: 'SQLite', icon: 'sqlite', category: 'database' },
  { id: 'firebase', name: 'Firebase', icon: 'firebase', category: 'database' },
  // More Hardware
  { id: 'ssd', name: 'SSD Storage', icon: 'ssd', category: 'hardware' },
  { id: 'gpu', name: 'GPU', icon: 'gpu', category: 'hardware' },
  { id: 'rack', name: 'Server Rack', icon: 'rack', category: 'hardware' },
  { id: 'nas', name: 'NAS Storage', icon: 'nas', category: 'hardware' },
  // Messaging/Queue
  { id: 'kafka', name: 'Kafka', icon: 'kafka', category: 'server' },
  { id: 'rabbitmq', name: 'RabbitMQ', icon: 'rabbitmq', category: 'server' },
  // Monitoring
  { id: 'grafana', name: 'Grafana', icon: 'grafana', category: 'server' },
  { id: 'prometheus', name: 'Prometheus', icon: 'prometheus', category: 'server' },
  // Gaming
  { id: 'gamepad', name: 'Gamepad', icon: 'gamepad', category: 'endpoint' },
  { id: 'vr_headset', name: 'VR Headset', icon: 'vr_headset', category: 'endpoint' },
  // AI/LLM Providers
  { id: 'openai', name: 'OpenAI', icon: 'openai', category: 'ai' },
  { id: 'anthropic', name: 'Anthropic', icon: 'anthropic', category: 'ai' },
  { id: 'google_ai', name: 'Google AI/Gemini', icon: 'google_ai', category: 'ai' },
  { id: 'meta_ai', name: 'Meta AI/Llama', icon: 'meta_ai', category: 'ai' },
  { id: 'deepseek', name: 'DeepSeek', icon: 'deepseek', category: 'ai' },
  { id: 'qwen', name: 'Qwen', icon: 'qwen', category: 'ai' },
  { id: 'mistral', name: 'Mistral AI', icon: 'mistral', category: 'ai' },
  { id: 'xai', name: 'xAI/Grok', icon: 'xai', category: 'ai' },
  { id: 'kimi', name: 'Kimi/Moonshot', icon: 'kimi', category: 'ai' },
  { id: 'zhipu', name: 'Zhipu AI', icon: 'zhipu', category: 'ai' },
  { id: 'cohere', name: 'Cohere', icon: 'cohere', category: 'ai' },
  { id: 'huggingface', name: 'Hugging Face', icon: 'huggingface', category: 'ai' },
  { id: 'ollama', name: 'Ollama', icon: 'ollama', category: 'ai' },
  { id: 'llm_generic', name: 'LLM/AI Model', icon: 'llm_generic', category: 'ai' },
  // Additional Network/Connectivity
  { id: 'satellite_dish', name: 'Satellite Dish', icon: 'satellite_dish', category: 'network' },
  { id: 'satellite_antenna', name: 'Satellite Antenna', icon: 'satellite_antenna', category: 'network' },
  { id: 'fibre_cable', name: 'Fibre Optic Cable', icon: 'fibre_cable', category: 'network' },
  { id: 'fibre_connector', name: 'Fibre Connector', icon: 'fibre_connector', category: 'network' },
  { id: 'network_jack', name: 'Network Jack', icon: 'network_jack', category: 'network' },
  { id: 'patch_panel', name: 'Patch Panel', icon: 'patch_panel', category: 'network' },
  { id: 'modem', name: 'Modem', icon: 'modem', category: 'network' },
  { id: 'repeater', name: 'Repeater', icon: 'repeater', category: 'network' },
  { id: 'bridge', name: 'Network Bridge', icon: 'bridge', category: 'network' },
  { id: 'gateway', name: 'Gateway', icon: 'gateway', category: 'network' },
  { id: 'proxy', name: 'Proxy Server', icon: 'proxy', category: 'server' },
  { id: 'cdn', name: 'CDN', icon: 'cdn', category: 'cloud' },
  { id: 'iot_device', name: 'IoT Device', icon: 'iot_device', category: 'endpoint' },
  { id: 'camera', name: 'IP Camera', icon: 'camera', category: 'endpoint' },
  { id: 'sensor', name: 'Sensor', icon: 'sensor', category: 'endpoint' },
];

// Status types for elements
type ElementStatus = 'none' | 'on_track' | 'at_risk' | 'blocked' | 'done';
type ElementPriority = 'none' | 'p1' | 'p2' | 'p3';

// Vote type
interface Vote {
  user_id: number;
  color: string; // dot color
}

// Types
interface WhiteboardElement {
  id?: number;
  element_id: string;
  element_type: 'rectangle' | 'ellipse' | 'line' | 'arrow' | 'bidirectional_arrow' | 'text' | 'sticky' | 'image' | 'freehand' | 'symbol' | 'triangle' | 'diamond' | 'hexagon' | 'star' | 'timer' | 'table' | 'connector' | 'code' | 'checklist' | 'link';
  x: number;
  y: number;
  width: number;
  height: number;
  rotation: number;
  fill_color: string | null;
  stroke_color: string;
  stroke_width: number;
  opacity: number;
  content?: string;
  font_size?: number;
  font_family?: string;
  text_align?: string;
  image_url?: string;
  points?: { x: number; y: number }[];
  z_index: number;
  created_by?: number;
  symbol_type?: string; // For network symbols
  label?: string; // Text label on shapes/symbols
  // Timer specific
  timer_duration?: number; // Duration in seconds
  timer_started_at?: number; // Timestamp when timer started
  timer_paused_at?: number; // Timestamp when paused (null if running)
  // Table specific
  table_rows?: number;
  table_cols?: number;
  table_data?: string[][];
  // Smart connector specific
  start_element_id?: string; // ID of element connector starts from
  end_element_id?: string; // ID of element connector ends at
  connector_style?: 'straight' | 'curved' | 'elbow';
  // Voting/Dot voting
  votes?: Vote[];
  // Status tags
  status?: ElementStatus;
  priority?: ElementPriority;
  // Gradient fill
  gradient?: { start: string; end: string; direction: 'horizontal' | 'vertical' | 'diagonal' };
  // Rich text formatting
  text_bold?: boolean;
  text_italic?: boolean;
  text_underline?: boolean;
  text_bullet_list?: boolean;
  // Code block specific
  code_language?: string;
  // Checklist specific
  checklist_items?: { id: string; text: string; checked: boolean }[];
  // AI category
  ai_category?: string;
  // Link/URL specific
  link_url?: string;
  link_title?: string;
  link_description?: string;
  link_favicon?: string;
  // Comments/Threads
  comments?: { id: string; user_id: number; username: string; text: string; created_at: string; mentions?: number[] }[];
  // Grouping
  group_id?: string;
  // Sticky note size
  sticky_size?: 'small' | 'medium' | 'large';
}

interface RemoteUser {
  user_id: number;
  username: string;
  cursor_x: number;
  cursor_y: number;
  color: string;
  selected_element_id: string | null;
}

interface Whiteboard {
  id: number;
  project_id: number;
  name: string;
  description?: string;
  canvas_width: number;
  canvas_height: number;
  background_color: string;
  grid_enabled: boolean;
  is_locked: boolean;
  elements: WhiteboardElement[];
}

type Tool = 'select' | 'pan' | 'rectangle' | 'ellipse' | 'triangle' | 'diamond' | 'hexagon' | 'star' | 'line' | 'arrow' | 'bidirectional_arrow' | 'text' | 'sticky' | 'freehand' | 'eraser' | 'symbol' | 'timer' | 'table' | 'connector' | 'code' | 'checklist' | 'link';

// Sticky note size presets
const STICKY_SIZES = {
  small: { width: 120, height: 100 },
  medium: { width: 200, height: 150 },
  large: { width: 300, height: 220 },
};

// Comment interface
interface ElementComment {
  id: string;
  user_id: number;
  username: string;
  text: string;
  created_at: string;
  mentions?: number[];
}

// Project collaborators for @mentions
interface Collaborator {
  user_id: number;
  username: string;
  email?: string;
  avatar_url?: string;
}

// Color palette
const COLORS = [
  '#ffffff', '#f8fafc', '#f1f5f9', '#e2e8f0',
  '#ef4444', '#f97316', '#f59e0b', '#eab308',
  '#22c55e', '#10b981', '#14b8a6', '#06b6d4',
  '#3b82f6', '#6366f1', '#8b5cf6', '#a855f7',
  '#ec4899', '#f43f5e', '#1e1e2e', '#000000',
];

const WhiteboardPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { user } = useAuth();
  const { whiteboardId, projectId: routeProjectId } = useParams<{ whiteboardId: string; projectId: string }>();
  const [searchParams] = useSearchParams();
  const projectId = routeProjectId || searchParams.get('projectId');
  
  // Debug logging
  console.log('WhiteboardPage render:', { whiteboardId, projectId, routeProjectId });

  // Canvas refs
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // State
  const [whiteboard, setWhiteboard] = useState<Whiteboard | null>(null);
  const [elements, setElements] = useState<WhiteboardElement[]>([]);
  const [selectedTool, setSelectedTool] = useState<Tool>('select');
  const [selectedElement, setSelectedElement] = useState<WhiteboardElement | null>(null);
  const [strokeColor, setStrokeColor] = useState('#ffffff');
  const [fillColor, setFillColor] = useState<string | null>(null);
  const [strokeWidth, setStrokeWidth] = useState(2);
  const [fontSize, setFontSize] = useState(16);
  
  // Canvas state
  const [zoom, setZoom] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [isDrawing, setIsDrawing] = useState(false);
  const [drawingElement, setDrawingElement] = useState<WhiteboardElement | null>(null);
  const [freehandPoints, setFreehandPoints] = useState<{ x: number; y: number }[]>([]);
  
  // Remote users
  const [remoteUsers, setRemoteUsers] = useState<RemoteUser[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  
  // Undo/Redo
  const [history, setHistory] = useState<WhiteboardElement[][]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);

  // Popovers
  const [colorAnchor, setColorAnchor] = useState<HTMLButtonElement | null>(null);
  const [colorType, setColorType] = useState<'stroke' | 'fill'>('stroke');
  
  // Grid and snackbar
  const [showGrid, setShowGrid] = useState(true);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({ open: false, message: '', severity: 'info' });
  
  // Clipboard for copy/paste (supports multiple elements)
  const [clipboard, setClipboard] = useState<WhiteboardElement[]>([]);
  
  // Dragging and resizing state
  const [isDragging, setIsDragging] = useState(false);
  const [isResizing, setIsResizing] = useState(false);
  const [resizeHandle, setResizeHandle] = useState<string | null>(null);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [elementStart, setElementStart] = useState({ x: 0, y: 0, width: 0, height: 0 });
  
  // Ref to track current tool synchronously (to avoid async state issues)
  const selectedToolRef = useRef(selectedTool);
  useEffect(() => {
    selectedToolRef.current = selectedTool;
  }, [selectedTool]);
  
  // Opacity control
  const [elementOpacity, setElementOpacity] = useState(1);
  
  // Image upload ref
  const imageInputRef = useRef<HTMLInputElement>(null);

  // Multi-select state
  const [multiSelection, setMultiSelection] = useState<string[]>([]);
  const [multiElementStartPositions, setMultiElementStartPositions] = useState<Record<string, { x: number; y: number }>>({});
  const [isSelectionBox, setIsSelectionBox] = useState(false);
  const [selectionBoxStart, setSelectionBoxStart] = useState({ x: 0, y: 0 });
  const [selectionBoxEnd, setSelectionBoxEnd] = useState({ x: 0, y: 0 });
  
  // Element locking
  const [lockedElements, setLockedElements] = useState<Set<string>>(new Set());
  
  // Snap to grid
  const [snapToGrid, setSnapToGrid] = useState(false);
  
  // Export format dialog
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  
  // Clear all confirmation dialog
  const [clearAllDialogOpen, setClearAllDialogOpen] = useState(false);
  
  // Templates dialog
  const [templatesDialogOpen, setTemplatesDialogOpen] = useState(false);
  
  // Connector drawing state
  const [connectorStart, setConnectorStart] = useState<{ elementId: string; x: number; y: number } | null>(null);
  
  // Status/Priority menu anchor
  const [statusMenuAnchor, setStatusMenuAnchor] = useState<HTMLElement | null>(null);
  
  // Vote colors for dot voting
  const VOTE_COLORS = ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6', '#8b5cf6'];
  const MAX_VOTES_PER_USER = 5;
  const GRID_SIZE = 20;
  
  // Text editing mode
  const [editingTextId, setEditingTextId] = useState<string | null>(null);
  const [editingText, setEditingText] = useState('');
  const textInputRef = useRef<HTMLInputElement>(null);
  // Store editing element position to prevent flickering during re-renders
  const editingElementRef = useRef<{
    x: number;
    y: number;
    width: number;
    height: number;
    fill_color?: string | null;
    stroke_color?: string | null;
    font_size?: number;
    element_type: string;
  } | null>(null);
  
  // Fullscreen mode
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Symbol tool state
  const [selectedSymbol, setSelectedSymbol] = useState<string | null>('router');
  const [symbolsAnchor, setSymbolsAnchor] = useState<HTMLButtonElement | null>(null);
  const [labelText, setLabelText] = useState('');
  
  // Context menu state
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; element: WhiteboardElement | null } | null>(null);

  // Search state
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<WhiteboardElement[]>([]);
  
  // Font selection
  const [selectedFont, setSelectedFont] = useState('Inter, sans-serif');
  const [fontMenuAnchor, setFontMenuAnchor] = useState<HTMLElement | null>(null);
  
  // Gradient dialog
  const [gradientDialogOpen, setGradientDialogOpen] = useState(false);
  const [selectedGradient, setSelectedGradient] = useState<{ start: string; end: string; direction: 'horizontal' | 'vertical' | 'diagonal' } | null>(null);
  
  // Sticky color picker
  const [stickyColorAnchor, setStickyColorAnchor] = useState<HTMLElement | null>(null);
  const [selectedStickyColor, setSelectedStickyColor] = useState('#fef08a');
  
  // AI features
  const [aiDialogOpen, setAiDialogOpen] = useState(false);
  const [aiDialogMode, setAiDialogMode] = useState<'summarize' | 'categorize' | 'generate' | 'autolayout'>('summarize');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState<string>('');
  const [aiPrompt, setAiPrompt] = useState('');

  // Link element state
  const [linkDialogOpen, setLinkDialogOpen] = useState(false);
  const [linkUrl, setLinkUrl] = useState('');
  const [linkTitle, setLinkTitle] = useState('');
  const [pendingLinkPosition, setPendingLinkPosition] = useState<{ x: number; y: number } | null>(null);
  
  // Comments panel state
  const [commentsPanelOpen, setCommentsPanelOpen] = useState(false);
  const [commentingElement, setCommentingElement] = useState<WhiteboardElement | null>(null);
  const [newCommentText, setNewCommentText] = useState('');
  
  // Mentions autocomplete state
  const [mentionsAnchor, setMentionsAnchor] = useState<HTMLElement | null>(null);
  const [mentionQuery, setMentionQuery] = useState('');
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  
  // Element grouping state
  const [elementGroups, setElementGroups] = useState<Record<string, string[]>>({});
  
  // Sticky note size state
  const [stickySizeMenuAnchor, setStickySizeMenuAnchor] = useState<HTMLElement | null>(null);
  const [selectedStickySize, setSelectedStickySize] = useState<'small' | 'medium' | 'large'>('medium');

  // Table cell editing state
  const [editingTableCell, setEditingTableCell] = useState<{ elementId: string; row: number; col: number } | null>(null);
  const [tableCellText, setTableCellText] = useState('');
  const tableCellInputRef = useRef<HTMLInputElement>(null);

  // Generate unique element ID
  const generateElementId = () => `el_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  // Generate unique group ID
  const generateGroupId = () => `grp_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  
  // Snap value to grid if snap is enabled
  const snapToGridValue = (value: number): number => {
    if (!snapToGrid) return value;
    return Math.round(value / GRID_SIZE) * GRID_SIZE;
  };
  
  // Track container size for canvas resize
  const [containerSize, setContainerSize] = useState({ width: 1200, height: 800 });

  // Load whiteboard data
  useEffect(() => {
    const loadWhiteboard = async () => {
      if (!whiteboardId) {
        console.log('No whiteboardId, skipping load');
        return;
      }
      
      try {
        console.log('Loading whiteboard:', whiteboardId);
        const data = await whiteboardClient.get(Number(whiteboardId));
        console.log('Whiteboard data loaded:', data);
        setWhiteboard(data);
        setElements(data.elements || []);
        
        // Initialize history
        setHistory([data.elements || []]);
        setHistoryIndex(0);
      } catch (error) {
        console.error('Failed to load whiteboard:', error);
        setSnackbar({ open: true, message: 'Failed to load whiteboard', severity: 'error' });
      }
    };
    
    loadWhiteboard();
  }, [whiteboardId]);
  
  // Handle container resize
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    
    const updateSize = () => {
      setContainerSize({
        width: container.clientWidth || 1200,
        height: container.clientHeight || 800,
      });
    };
    
    // Initial size
    updateSize();
    
    // Observe resize
    const resizeObserver = new ResizeObserver(updateSize);
    resizeObserver.observe(container);
    
    return () => resizeObserver.disconnect();
  }, []);

  // Connect WebSocket with reconnection
  useEffect(() => {
    if (!whiteboardId) return;

    let ws: WebSocket | null = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 5;
    let reconnectTimeout: NodeJS.Timeout | null = null;

    const connect = () => {
      const token = localStorage.getItem('vragent_access_token');
      if (!token) return;

      const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/whiteboard/${whiteboardId}?token=${token}`;
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('WebSocket connected');
        reconnectAttempts = 0;
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      ws.onclose = () => {
        console.log('WebSocket disconnected');
        if (reconnectAttempts < maxReconnectAttempts) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 10000);
          reconnectAttempts++;
          console.log(`Reconnecting in ${delay}ms (attempt ${reconnectAttempts}/${maxReconnectAttempts})`);
          reconnectTimeout = setTimeout(connect, delay);
        }
      };

      wsRef.current = ws;
    };

    connect();

    return () => {
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, [whiteboardId]);

  const handleWebSocketMessage = (data: any) => {
    switch (data.type) {
      case 'current_users':
        setRemoteUsers(data.users);
        break;
      case 'user_joined':
        setRemoteUsers(prev => [...prev, {
          user_id: data.user_id,
          username: data.username,
          color: data.color,
          cursor_x: 0,
          cursor_y: 0,
          selected_element_id: null,
        }]);
        break;
      case 'user_left':
        setRemoteUsers(prev => prev.filter(u => u.user_id !== data.user_id));
        break;
      case 'cursor_move':
        setRemoteUsers(prev => prev.map(u => 
          u.user_id === data.user_id 
            ? { ...u, cursor_x: data.cursor_x, cursor_y: data.cursor_y }
            : u
        ));
        break;
      case 'selection_change':
        setRemoteUsers(prev => prev.map(u =>
          u.user_id === data.user_id
            ? { ...u, selected_element_id: data.element_id }
            : u
        ));
        break;
      case 'element_create':
        setElements(prev => [...prev, data.element]);
        break;
      case 'element_update':
        setElements(prev => prev.map(el =>
          el.element_id === data.element_id
            ? { ...el, ...data.updates }
            : el
        ));
        break;
      case 'element_delete':
        setElements(prev => prev.filter(el => el.element_id !== data.element_id));
        break;
    }
  };

  // Send WebSocket message
  const sendWsMessage = (message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    }
  };

  // Canvas rendering
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size from tracked container size
    canvas.width = containerSize.width;
    canvas.height = containerSize.height;

    // Clear canvas with background color
    ctx.fillStyle = whiteboard?.background_color || '#1e1e2e';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Apply transformations
    ctx.save();
    ctx.translate(panOffset.x, panOffset.y);
    ctx.scale(zoom, zoom);

    // Draw grid if enabled
    if (showGrid) {
      drawGrid(ctx, canvas.width, canvas.height);
    }

    // Draw elements
    elements.forEach(element => {
      drawElement(ctx, element);
      
      // Draw lock indicator
      if (lockedElements.has(element.element_id)) {
        ctx.save();
        ctx.fillStyle = alpha('#f59e0b', 0.8);
        ctx.beginPath();
        ctx.arc(element.x + element.width - 10, element.y + 10, 8, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#1e1e2e';
        ctx.font = '10px Inter';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('🔒', element.x + element.width - 10, element.y + 10);
        ctx.restore();
      }
      
      // Draw multi-selection highlight
      if (multiSelection.includes(element.element_id)) {
        ctx.strokeStyle = '#22c55e';
        ctx.lineWidth = 2;
        ctx.setLineDash([5, 5]);
        ctx.strokeRect(element.x - 3, element.y - 3, element.width + 6, element.height + 6);
        ctx.setLineDash([]);
      }
    });

    // Draw current drawing element
    if (drawingElement) {
      drawElement(ctx, drawingElement);
    }

    // Draw selection
    if (selectedElement) {
      drawSelection(ctx, selectedElement);
    }

    // Draw marquee selection box
    if (isSelectionBox) {
      const x = Math.min(selectionBoxStart.x, selectionBoxEnd.x);
      const y = Math.min(selectionBoxStart.y, selectionBoxEnd.y);
      const width = Math.abs(selectionBoxEnd.x - selectionBoxStart.x);
      const height = Math.abs(selectionBoxEnd.y - selectionBoxStart.y);
      
      ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
      ctx.fillRect(x, y, width, height);
      ctx.strokeStyle = '#3b82f6';
      ctx.lineWidth = 1;
      ctx.setLineDash([5, 5]);
      ctx.strokeRect(x, y, width, height);
      ctx.setLineDash([]);
    }

    ctx.restore();

    // Draw remote cursors (not transformed)
    drawRemoteCursors(ctx);

  }, [elements, whiteboard, zoom, panOffset, drawingElement, selectedElement, remoteUsers, multiSelection, lockedElements, showGrid, containerSize, isSelectionBox, selectionBoxStart, selectionBoxEnd]);

  const drawGrid = (ctx: CanvasRenderingContext2D, width: number, height: number) => {
    ctx.strokeStyle = alpha('#ffffff', 0.1);
    ctx.lineWidth = 1;

    const gridSize = 20;
    const startX = Math.floor(-panOffset.x / zoom / gridSize) * gridSize;
    const startY = Math.floor(-panOffset.y / zoom / gridSize) * gridSize;
    const endX = startX + width / zoom + gridSize;
    const endY = startY + height / zoom + gridSize;

    for (let x = startX; x < endX; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, startY);
      ctx.lineTo(x, endY);
      ctx.stroke();
    }

    for (let y = startY; y < endY; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(startX, y);
      ctx.lineTo(endX, y);
      ctx.stroke();
    }
  };

  const drawElement = (ctx: CanvasRenderingContext2D, element: WhiteboardElement) => {
    ctx.save();
    ctx.globalAlpha = element.opacity || 1;

    // Helper to create gradient if element has gradient property
    const createGradient = () => {
      if (element.gradient) {
        let grad;
        if (element.gradient.direction === 'horizontal') {
          grad = ctx.createLinearGradient(element.x, element.y, element.x + element.width, element.y);
        } else if (element.gradient.direction === 'vertical') {
          grad = ctx.createLinearGradient(element.x, element.y, element.x, element.y + element.height);
        } else {
          grad = ctx.createLinearGradient(element.x, element.y, element.x + element.width, element.y + element.height);
        }
        grad.addColorStop(0, element.gradient.start);
        grad.addColorStop(1, element.gradient.end);
        return grad;
      }
      return element.fill_color;
    };

    switch (element.element_type) {
      case 'rectangle':
        if (element.fill_color || element.gradient) {
          ctx.fillStyle = createGradient() || element.fill_color || '#ffffff';
          ctx.fillRect(element.x, element.y, element.width, element.height);
        }
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.strokeRect(element.x, element.y, element.width, element.height);
        break;

      case 'ellipse':
        ctx.beginPath();
        ctx.ellipse(
          element.x + element.width / 2,
          element.y + element.height / 2,
          element.width / 2,
          element.height / 2,
          0, 0, Math.PI * 2
        );
        if (element.fill_color || element.gradient) {
          ctx.fillStyle = createGradient() || element.fill_color || '#ffffff';
          ctx.fill();
        }
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();
        break;

      case 'line':
      case 'arrow':
        ctx.beginPath();
        ctx.moveTo(element.x, element.y);
        ctx.lineTo(element.x + element.width, element.y + element.height);
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();

        if (element.element_type === 'arrow') {
          // Draw arrowhead
          const angle = Math.atan2(element.height, element.width);
          const headLen = 15;
          const endX = element.x + element.width;
          const endY = element.y + element.height;

          ctx.beginPath();
          ctx.moveTo(endX, endY);
          ctx.lineTo(
            endX - headLen * Math.cos(angle - Math.PI / 6),
            endY - headLen * Math.sin(angle - Math.PI / 6)
          );
          ctx.moveTo(endX, endY);
          ctx.lineTo(
            endX - headLen * Math.cos(angle + Math.PI / 6),
            endY - headLen * Math.sin(angle + Math.PI / 6)
          );
          ctx.stroke();
        }
        break;

      case 'text':
        const fontStyle = `${element.text_italic ? 'italic ' : ''}${element.text_bold ? 'bold ' : ''}`;
        ctx.font = `${fontStyle}${element.font_size || 16}px ${element.font_family || 'Inter, sans-serif'}`;
        ctx.fillStyle = element.stroke_color;
        ctx.textAlign = (element.text_align as CanvasTextAlign) || 'left';
        
        // Handle multiline text
        const textContent = element.content || '';
        const textLines = textContent.split('\n');
        const lineHeight = (element.font_size || 16) * 1.4;
        
        textLines.forEach((line, lineIndex) => {
          const yPos = element.y + (element.font_size || 16) + (lineIndex * lineHeight);
          ctx.fillText(line, element.x, yPos);
          
          if (element.text_underline) {
            const textWidth = ctx.measureText(line).width;
            ctx.beginPath();
            ctx.moveTo(element.x, yPos + 2);
            ctx.lineTo(element.x + textWidth, yPos + 2);
            ctx.strokeStyle = element.stroke_color;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        });
        break;

      case 'sticky':
        // Draw sticky note background
        ctx.fillStyle = element.fill_color || '#fef08a';
        ctx.shadowColor = 'rgba(0, 0, 0, 0.2)';
        ctx.shadowBlur = 10;
        ctx.shadowOffsetY = 5;
        ctx.fillRect(element.x, element.y, element.width, element.height);
        ctx.shadowColor = 'transparent';

        // Draw text
        if (element.content) {
          ctx.font = `${element.font_size || 14}px ${element.font_family || 'Inter'}`;
          ctx.fillStyle = '#1e1e2e';
          const lines = element.content.split('\n');
          lines.forEach((line, i) => {
            ctx.fillText(line, element.x + 10, element.y + 25 + i * 20);
          });
        }
        break;

      case 'freehand':
        if (element.points && element.points.length > 1) {
          ctx.beginPath();
          ctx.moveTo(element.points[0].x, element.points[0].y);
          for (let i = 1; i < element.points.length; i++) {
            ctx.lineTo(element.points[i].x, element.points[i].y);
          }
          ctx.strokeStyle = element.stroke_color;
          ctx.lineWidth = element.stroke_width;
          ctx.lineCap = 'round';
          ctx.lineJoin = 'round';
          ctx.stroke();
        }
        break;

      case 'image':
        if (element.content) {
          const img = new Image();
          img.src = element.content;
          if (img.complete) {
            ctx.drawImage(img, element.x, element.y, element.width, element.height);
          } else {
            // Image not loaded yet, draw placeholder
            ctx.fillStyle = '#2d2d3d';
            ctx.fillRect(element.x, element.y, element.width, element.height);
            ctx.strokeStyle = '#666';
            ctx.lineWidth = 2;
            ctx.strokeRect(element.x, element.y, element.width, element.height);
            ctx.fillStyle = '#888';
            ctx.font = '14px Inter';
            ctx.textAlign = 'center';
            ctx.fillText('Loading...', element.x + element.width / 2, element.y + element.height / 2);
          }
        }
        break;

      case 'symbol':
        drawNetworkSymbol(ctx, element);
        break;

      case 'triangle':
        ctx.beginPath();
        ctx.moveTo(element.x + element.width / 2, element.y);
        ctx.lineTo(element.x + element.width, element.y + element.height);
        ctx.lineTo(element.x, element.y + element.height);
        ctx.closePath();
        if (element.fill_color) {
          ctx.fillStyle = element.fill_color;
          ctx.fill();
        }
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();
        break;

      case 'diamond':
        ctx.beginPath();
        ctx.moveTo(element.x + element.width / 2, element.y);
        ctx.lineTo(element.x + element.width, element.y + element.height / 2);
        ctx.lineTo(element.x + element.width / 2, element.y + element.height);
        ctx.lineTo(element.x, element.y + element.height / 2);
        ctx.closePath();
        if (element.fill_color) {
          ctx.fillStyle = element.fill_color;
          ctx.fill();
        }
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();
        break;

      case 'hexagon':
        const hx = element.x;
        const hy = element.y;
        const hw = element.width;
        const hh = element.height;
        ctx.beginPath();
        ctx.moveTo(hx + hw * 0.25, hy);
        ctx.lineTo(hx + hw * 0.75, hy);
        ctx.lineTo(hx + hw, hy + hh / 2);
        ctx.lineTo(hx + hw * 0.75, hy + hh);
        ctx.lineTo(hx + hw * 0.25, hy + hh);
        ctx.lineTo(hx, hy + hh / 2);
        ctx.closePath();
        if (element.fill_color) {
          ctx.fillStyle = element.fill_color;
          ctx.fill();
        }
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();
        break;

      case 'star':
        const sx = element.x + element.width / 2;
        const sy = element.y + element.height / 2;
        const outerRadius = Math.min(element.width, element.height) / 2;
        const innerRadius = outerRadius * 0.4;
        const spikes = 5;
        ctx.beginPath();
        for (let i = 0; i < spikes * 2; i++) {
          const radius = i % 2 === 0 ? outerRadius : innerRadius;
          const angle = (i * Math.PI / spikes) - Math.PI / 2;
          const px = sx + Math.cos(angle) * radius;
          const py = sy + Math.sin(angle) * radius;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        if (element.fill_color) {
          ctx.fillStyle = element.fill_color;
          ctx.fill();
        }
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();
        break;

      case 'bidirectional_arrow':
        // Draw line
        ctx.beginPath();
        ctx.moveTo(element.x, element.y);
        ctx.lineTo(element.x + element.width, element.y + element.height);
        ctx.strokeStyle = element.stroke_color;
        ctx.lineWidth = element.stroke_width;
        ctx.stroke();
        // Calculate angle
        const biAngle = Math.atan2(element.height, element.width);
        const biHeadLen = 15;
        // Arrow at end
        const biEndX = element.x + element.width;
        const biEndY = element.y + element.height;
        ctx.beginPath();
        ctx.moveTo(biEndX, biEndY);
        ctx.lineTo(biEndX - biHeadLen * Math.cos(biAngle - Math.PI / 6), biEndY - biHeadLen * Math.sin(biAngle - Math.PI / 6));
        ctx.moveTo(biEndX, biEndY);
        ctx.lineTo(biEndX - biHeadLen * Math.cos(biAngle + Math.PI / 6), biEndY - biHeadLen * Math.sin(biAngle + Math.PI / 6));
        ctx.stroke();
        // Arrow at start
        const biStartX = element.x;
        const biStartY = element.y;
        const reverseAngle = biAngle + Math.PI;
        ctx.beginPath();
        ctx.moveTo(biStartX, biStartY);
        ctx.lineTo(biStartX - biHeadLen * Math.cos(reverseAngle - Math.PI / 6), biStartY - biHeadLen * Math.sin(reverseAngle - Math.PI / 6));
        ctx.moveTo(biStartX, biStartY);
        ctx.lineTo(biStartX - biHeadLen * Math.cos(reverseAngle + Math.PI / 6), biStartY - biHeadLen * Math.sin(reverseAngle + Math.PI / 6));
        ctx.stroke();
        break;

      case 'timer':
        // Draw timer circle with countdown
        const timerCenterX = element.x + element.width / 2;
        const timerCenterY = element.y + element.height / 2;
        const timerRadius = Math.min(element.width, element.height) / 2 - 5;
        
        // Background circle
        ctx.beginPath();
        ctx.arc(timerCenterX, timerCenterY, timerRadius, 0, Math.PI * 2);
        ctx.fillStyle = element.fill_color || '#1e293b';
        ctx.fill();
        ctx.strokeStyle = element.stroke_color || '#3b82f6';
        ctx.lineWidth = 4;
        ctx.stroke();
        
        // Calculate remaining time
        const duration = element.timer_duration || 60;
        let remaining = duration;
        if (element.timer_started_at && !element.timer_paused_at) {
          const elapsed = (Date.now() - element.timer_started_at) / 1000;
          remaining = Math.max(0, duration - elapsed);
        } else if (element.timer_paused_at && element.timer_started_at) {
          const elapsed = (element.timer_paused_at - element.timer_started_at) / 1000;
          remaining = Math.max(0, duration - elapsed);
        }
        
        // Progress arc
        const progress = remaining / duration;
        ctx.beginPath();
        ctx.arc(timerCenterX, timerCenterY, timerRadius - 8, -Math.PI / 2, -Math.PI / 2 + (progress * Math.PI * 2), false);
        ctx.strokeStyle = progress > 0.25 ? '#22c55e' : progress > 0.1 ? '#eab308' : '#ef4444';
        ctx.lineWidth = 8;
        ctx.lineCap = 'round';
        ctx.stroke();
        
        // Display time
        const mins = Math.floor(remaining / 60);
        const secs = Math.floor(remaining % 60);
        const timeStr = `${mins}:${secs.toString().padStart(2, '0')}`;
        ctx.font = `bold ${timerRadius * 0.5}px Inter`;
        ctx.fillStyle = '#ffffff';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(timeStr, timerCenterX, timerCenterY);
        break;

      case 'table':
        // Draw table grid
        const rows = element.table_rows || 3;
        const cols = element.table_cols || 3;
        const cellWidth = element.width / cols;
        const cellHeight = element.height / rows;
        
        // Fill background
        ctx.fillStyle = element.fill_color || '#1e293b';
        ctx.fillRect(element.x, element.y, element.width, element.height);
        
        // Draw grid lines
        ctx.strokeStyle = element.stroke_color || '#64748b';
        ctx.lineWidth = element.stroke_width || 1;
        
        // Vertical lines
        for (let i = 0; i <= cols; i++) {
          ctx.beginPath();
          ctx.moveTo(element.x + i * cellWidth, element.y);
          ctx.lineTo(element.x + i * cellWidth, element.y + element.height);
          ctx.stroke();
        }
        
        // Horizontal lines
        for (let i = 0; i <= rows; i++) {
          ctx.beginPath();
          ctx.moveTo(element.x, element.y + i * cellHeight);
          ctx.lineTo(element.x + element.width, element.y + i * cellHeight);
          ctx.stroke();
        }
        
        // Draw cell content if available
        if (element.table_data) {
          ctx.font = `${element.font_size || 12}px ${element.font_family || 'Inter'}`;
          ctx.fillStyle = '#ffffff';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          for (let r = 0; r < rows && r < element.table_data.length; r++) {
            for (let c = 0; c < cols && c < (element.table_data[r]?.length || 0); c++) {
              const text = element.table_data[r][c] || '';
              ctx.fillText(
                text,
                element.x + c * cellWidth + cellWidth / 2,
                element.y + r * cellHeight + cellHeight / 2
              );
            }
          }
        }
        break;

      case 'connector':
        // Smart connector - draw line between connected elements
        ctx.strokeStyle = element.stroke_color || '#64748b';
        ctx.lineWidth = element.stroke_width || 2;
        
        const startEl = elements.find(e => e.element_id === element.start_element_id);
        const endEl = elements.find(e => e.element_id === element.end_element_id);
        
        let startX = element.x;
        let startY = element.y;
        let endX = element.x + element.width;
        let endY = element.y + element.height;
        
        // If connected to elements, use their centers
        if (startEl) {
          startX = startEl.x + startEl.width / 2;
          startY = startEl.y + startEl.height / 2;
        }
        if (endEl) {
          endX = endEl.x + endEl.width / 2;
          endY = endEl.y + endEl.height / 2;
        }
        
        ctx.beginPath();
        if (element.connector_style === 'curved') {
          // Bezier curve
          const midX = (startX + endX) / 2;
          const midY = (startY + endY) / 2;
          const ctrlOffset = Math.abs(endX - startX) * 0.3;
          ctx.moveTo(startX, startY);
          ctx.bezierCurveTo(startX + ctrlOffset, startY, endX - ctrlOffset, endY, endX, endY);
        } else if (element.connector_style === 'elbow') {
          // Right-angle elbow
          const midX = (startX + endX) / 2;
          ctx.moveTo(startX, startY);
          ctx.lineTo(midX, startY);
          ctx.lineTo(midX, endY);
          ctx.lineTo(endX, endY);
        } else {
          // Straight line
          ctx.moveTo(startX, startY);
          ctx.lineTo(endX, endY);
        }
        ctx.stroke();
        
        // Draw arrow at end
        const angle = Math.atan2(endY - startY, endX - startX);
        const headLen = 12;
        ctx.beginPath();
        ctx.moveTo(endX, endY);
        ctx.lineTo(endX - headLen * Math.cos(angle - Math.PI / 6), endY - headLen * Math.sin(angle - Math.PI / 6));
        ctx.moveTo(endX, endY);
        ctx.lineTo(endX - headLen * Math.cos(angle + Math.PI / 6), endY - headLen * Math.sin(angle + Math.PI / 6));
        ctx.stroke();
        
        // Draw connection points (circles at endpoints)
        ctx.fillStyle = '#3b82f6';
        ctx.beginPath();
        ctx.arc(startX, startY, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(endX, endY, 5, 0, Math.PI * 2);
        ctx.fill();
        break;

      case 'code':
        // Draw code block background
        ctx.fillStyle = '#1e1e2e';
        ctx.shadowColor = 'rgba(0, 0, 0, 0.3)';
        ctx.shadowBlur = 8;
        ctx.fillRect(element.x, element.y, element.width, element.height);
        ctx.shadowColor = 'transparent';
        
        // Draw header bar with language label
        ctx.fillStyle = '#374151';
        ctx.fillRect(element.x, element.y, element.width, 28);
        
        // Language label
        ctx.font = '12px "Courier New", monospace';
        ctx.fillStyle = '#9ca3af';
        ctx.textAlign = 'left';
        ctx.fillText(element.code_language || 'code', element.x + 10, element.y + 18);
        
        // Code content
        ctx.font = '14px "Courier New", monospace';
        ctx.fillStyle = '#e5e7eb';
        ctx.textAlign = 'left';
        const codeLines = (element.content || '// Your code here').split('\n');
        codeLines.forEach((line, i) => {
          if (element.y + 50 + i * 20 < element.y + element.height - 10) {
            ctx.fillText(line, element.x + 10, element.y + 50 + i * 20);
          }
        });
        
        // Border
        ctx.strokeStyle = '#4b5563';
        ctx.lineWidth = 1;
        ctx.strokeRect(element.x, element.y, element.width, element.height);
        break;

      case 'checklist':
        // Draw checklist background
        ctx.fillStyle = element.fill_color || '#ffffff';
        ctx.shadowColor = 'rgba(0, 0, 0, 0.1)';
        ctx.shadowBlur = 6;
        ctx.fillRect(element.x, element.y, element.width, element.height);
        ctx.shadowColor = 'transparent';
        
        // Draw border
        ctx.strokeStyle = element.stroke_color || '#e5e7eb';
        ctx.lineWidth = 1;
        ctx.strokeRect(element.x, element.y, element.width, element.height);
        
        // Draw title
        ctx.font = 'bold 14px Inter, sans-serif';
        ctx.fillStyle = '#1f2937';
        ctx.textAlign = 'left';
        ctx.fillText(element.label || 'Checklist', element.x + 10, element.y + 22);
        
        // Draw checklist items
        const items = element.checklist_items || [];
        items.forEach((item, i) => {
          const itemY = element.y + 45 + i * 28;
          if (itemY < element.y + element.height - 15) {
            // Checkbox
            ctx.strokeStyle = '#9ca3af';
            ctx.lineWidth = 1.5;
            ctx.strokeRect(element.x + 12, itemY - 10, 16, 16);
            
            if (item.checked) {
              // Draw checkmark
              ctx.strokeStyle = '#22c55e';
              ctx.lineWidth = 2;
              ctx.beginPath();
              ctx.moveTo(element.x + 15, itemY - 2);
              ctx.lineTo(element.x + 20, itemY + 3);
              ctx.lineTo(element.x + 26, itemY - 6);
              ctx.stroke();
            }
            
            // Item text
            ctx.font = `${item.checked ? 'italic' : 'normal'} 13px Inter, sans-serif`;
            ctx.fillStyle = item.checked ? '#9ca3af' : '#374151';
            ctx.textAlign = 'left';
            const displayText = item.checked ? `${item.text}` : item.text;
            ctx.fillText(displayText, element.x + 36, itemY + 1);
            
            // Strikethrough for checked items
            if (item.checked) {
              const textWidth = ctx.measureText(displayText).width;
              ctx.beginPath();
              ctx.moveTo(element.x + 36, itemY - 2);
              ctx.lineTo(element.x + 36 + textWidth, itemY - 2);
              ctx.strokeStyle = '#9ca3af';
              ctx.lineWidth = 1;
              ctx.stroke();
            }
          }
        });
        break;

      case 'link':
        // Draw link card background
        ctx.fillStyle = '#ffffff';
        ctx.shadowColor = 'rgba(0, 0, 0, 0.15)';
        ctx.shadowBlur = 10;
        ctx.beginPath();
        ctx.roundRect(element.x, element.y, element.width, element.height, 8);
        ctx.fill();
        ctx.shadowColor = 'transparent';
        
        // Draw border
        ctx.strokeStyle = '#e5e7eb';
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(element.x, element.y, element.width, element.height, 8);
        ctx.stroke();
        
        // Draw link icon
        ctx.fillStyle = '#3b82f6';
        ctx.beginPath();
        ctx.arc(element.x + 24, element.y + 24, 14, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#ffffff';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('🔗', element.x + 24, element.y + 24);
        
        // Draw title
        ctx.font = 'bold 14px Inter, sans-serif';
        ctx.fillStyle = '#1f2937';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        const linkTitle = element.link_title || element.link_url || 'Link';
        const truncatedTitle = linkTitle.length > 30 ? linkTitle.substring(0, 30) + '...' : linkTitle;
        ctx.fillText(truncatedTitle, element.x + 48, element.y + 12);
        
        // Draw URL
        ctx.font = '11px Inter, sans-serif';
        ctx.fillStyle = '#6b7280';
        const displayUrl = element.link_url || 'https://...';
        const truncatedUrl = displayUrl.length > 40 ? displayUrl.substring(0, 40) + '...' : displayUrl;
        ctx.fillText(truncatedUrl, element.x + 48, element.y + 32);
        
        // Draw "Open" indicator
        ctx.fillStyle = '#3b82f6';
        ctx.font = '10px Inter, sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText('↗ Open', element.x + element.width - 8, element.y + element.height - 10);
        break;
    }

    // Draw comment indicator if has comments
    if (element.comments && element.comments.length > 0) {
      const commentX = element.x + element.width - 8;
      const commentY = element.y + element.height - 8;
      
      ctx.fillStyle = '#f59e0b';
      ctx.beginPath();
      ctx.arc(commentX, commentY, 10, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 10px Inter';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(String(element.comments.length), commentX, commentY);
    }

    // Draw group indicator if grouped
    if (element.group_id) {
      ctx.strokeStyle = '#8b5cf6';
      ctx.lineWidth = 2;
      ctx.setLineDash([4, 4]);
      ctx.strokeRect(element.x - 2, element.y - 2, element.width + 4, element.height + 4);
      ctx.setLineDash([]);
    }

    // Draw AI category badge if present
    if (element.ai_category) {
      ctx.font = '10px Inter, sans-serif';
      const catWidth = ctx.measureText(element.ai_category).width + 12;
      ctx.fillStyle = '#8b5cf6';
      ctx.beginPath();
      ctx.roundRect(element.x, element.y - 20, catWidth, 16, 4);
      ctx.fill();
      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(element.ai_category, element.x + 6, element.y - 12);
    }

    // Draw status badge if present
    if (element.status && element.status !== 'none') {
      const badgeColors: Record<ElementStatus, { bg: string; text: string; label: string }> = {
        'none': { bg: '', text: '', label: '' },
        'on_track': { bg: '#22c55e', text: '#ffffff', label: '✓' },
        'at_risk': { bg: '#f59e0b', text: '#000000', label: '!' },
        'blocked': { bg: '#ef4444', text: '#ffffff', label: '✕' },
        'done': { bg: '#3b82f6', text: '#ffffff', label: '✓' },
      };
      const badge = badgeColors[element.status];
      const badgeX = element.x + element.width - 12;
      const badgeY = element.y - 8;
      
      ctx.fillStyle = badge.bg;
      ctx.beginPath();
      ctx.arc(badgeX, badgeY, 10, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillStyle = badge.text;
      ctx.font = 'bold 12px Inter';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(badge.label, badgeX, badgeY);
    }

    // Draw priority badge if present
    if (element.priority && element.priority !== 'none') {
      const priorityColors: Record<ElementPriority, { bg: string; text: string }> = {
        'none': { bg: '', text: '' },
        'p1': { bg: '#ef4444', text: '#ffffff' },
        'p2': { bg: '#f59e0b', text: '#000000' },
        'p3': { bg: '#3b82f6', text: '#ffffff' },
      };
      const pBadge = priorityColors[element.priority];
      const pBadgeX = element.x - 8;
      const pBadgeY = element.y - 8;
      
      ctx.fillStyle = pBadge.bg;
      ctx.beginPath();
      ctx.roundRect(pBadgeX - 10, pBadgeY - 8, 20, 16, 3);
      ctx.fill();
      ctx.fillStyle = pBadge.text;
      ctx.font = 'bold 10px Inter';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(element.priority.toUpperCase(), pBadgeX, pBadgeY);
    }

    // Draw votes/dots if present
    if (element.votes && element.votes.length > 0) {
      const votesByColor: Record<string, number> = {};
      element.votes.forEach(v => {
        votesByColor[v.color] = (votesByColor[v.color] || 0) + 1;
      });
      
      let dotX = element.x + 5;
      const dotY = element.y + element.height + 15;
      
      Object.entries(votesByColor).forEach(([color, count]) => {
        // Draw dot
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(dotX, dotY, 8, 0, Math.PI * 2);
        ctx.fill();
        
        // Draw count if > 1
        if (count > 1) {
          ctx.fillStyle = '#ffffff';
          ctx.font = 'bold 10px Inter';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(count.toString(), dotX, dotY);
        }
        dotX += 20;
      });
    }

    // Draw label if present (for shapes and symbols)
    if (element.label && ['rectangle', 'ellipse', 'symbol', 'triangle', 'diamond', 'hexagon', 'star'].includes(element.element_type)) {
      ctx.font = `${element.font_size || 12}px ${element.font_family || 'Inter'}`;
      ctx.fillStyle = element.stroke_color || '#ffffff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      // Draw label below the element
      const labelY = element.votes && element.votes.length > 0 ? element.y + element.height + 30 : element.y + element.height + 5;
      ctx.fillText(element.label, element.x + element.width / 2, labelY);
    }

    ctx.restore();
  };

  // Draw network symbols on canvas
  const drawNetworkSymbol = (ctx: CanvasRenderingContext2D, element: WhiteboardElement) => {
    const { x, y, width, height, fill_color, stroke_color, stroke_width, symbol_type } = element;
    const centerX = x + width / 2;
    const centerY = y + height / 2;
    const size = Math.min(width, height);
    
    ctx.strokeStyle = stroke_color || '#3b82f6';
    ctx.lineWidth = stroke_width || 2;
    ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
    
    switch (symbol_type) {
      case 'router':
        // Router: cylinder shape with arrows
        ctx.beginPath();
        ctx.ellipse(centerX, y + size * 0.15, size * 0.4, size * 0.15, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.1, y + size * 0.15);
        ctx.lineTo(x + width * 0.1, y + size * 0.75);
        ctx.ellipse(centerX, y + size * 0.75, size * 0.4, size * 0.15, 0, Math.PI, 0);
        ctx.lineTo(x + width * 0.9, y + size * 0.15);
        ctx.fill();
        ctx.stroke();
        // Arrows
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.15, centerY);
        ctx.lineTo(centerX + size * 0.15, centerY);
        ctx.moveTo(centerX + size * 0.08, centerY - 6);
        ctx.lineTo(centerX + size * 0.15, centerY);
        ctx.lineTo(centerX + size * 0.08, centerY + 6);
        ctx.stroke();
        break;

      case 'switch':
        // Switch: rectangular box with ports
        ctx.fillRect(x + width * 0.1, y + height * 0.3, width * 0.8, height * 0.4);
        ctx.strokeRect(x + width * 0.1, y + height * 0.3, width * 0.8, height * 0.4);
        // Ports (small rectangles)
        for (let i = 0; i < 4; i++) {
          const portX = x + width * 0.2 + i * width * 0.17;
          ctx.fillStyle = '#22c55e';
          ctx.fillRect(portX, y + height * 0.45, width * 0.08, height * 0.1);
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'hub':
        // Hub: simple circle with spokes
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        for (let i = 0; i < 8; i++) {
          const angle = (i / 8) * Math.PI * 2;
          ctx.beginPath();
          ctx.moveTo(centerX, centerY);
          ctx.lineTo(centerX + Math.cos(angle) * size * 0.35, centerY + Math.sin(angle) * size * 0.35);
          ctx.stroke();
        }
        break;

      case 'firewall':
        // Firewall: brick wall pattern
        ctx.fillRect(x + width * 0.1, y + height * 0.2, width * 0.8, height * 0.6);
        ctx.strokeRect(x + width * 0.1, y + height * 0.2, width * 0.8, height * 0.6);
        ctx.strokeStyle = '#ef4444';
        // Brick lines
        for (let row = 0; row < 3; row++) {
          const rowY = y + height * 0.2 + row * height * 0.2;
          ctx.beginPath();
          ctx.moveTo(x + width * 0.1, rowY + height * 0.2);
          ctx.lineTo(x + width * 0.9, rowY + height * 0.2);
          ctx.stroke();
          for (let col = 0; col < 3; col++) {
            const offset = row % 2 === 0 ? 0 : width * 0.13;
            ctx.beginPath();
            ctx.moveTo(x + width * 0.1 + offset + col * width * 0.27, rowY);
            ctx.lineTo(x + width * 0.1 + offset + col * width * 0.27, rowY + height * 0.2);
            ctx.stroke();
          }
        }
        ctx.strokeStyle = stroke_color || '#3b82f6';
        break;

      case 'wireless':
        // Wireless AP: antenna with signal waves
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.7);
        ctx.lineTo(centerX, y + height * 0.3);
        ctx.stroke();
        // Signal waves
        for (let i = 1; i <= 3; i++) {
          ctx.beginPath();
          ctx.arc(centerX, y + height * 0.3, size * 0.1 * i, -Math.PI * 0.8, -Math.PI * 0.2);
          ctx.stroke();
        }
        // Base
        ctx.beginPath();
        ctx.ellipse(centerX, y + height * 0.75, size * 0.2, size * 0.08, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        break;

      case 'server':
        // Server: stacked rectangles
        for (let i = 0; i < 3; i++) {
          const rectY = y + height * 0.15 + i * height * 0.25;
          ctx.fillRect(x + width * 0.15, rectY, width * 0.7, height * 0.2);
          ctx.strokeRect(x + width * 0.15, rectY, width * 0.7, height * 0.2);
          // LED indicator
          ctx.fillStyle = '#22c55e';
          ctx.beginPath();
          ctx.arc(x + width * 0.25, rectY + height * 0.1, 4, 0, Math.PI * 2);
          ctx.fill();
          ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        }
        break;

      case 'database':
        // Database: cylinder
        ctx.beginPath();
        ctx.ellipse(centerX, y + size * 0.15, size * 0.35, size * 0.15, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + size * 0.15);
        ctx.lineTo(x + width * 0.15, y + size * 0.8);
        ctx.ellipse(centerX, y + size * 0.8, size * 0.35, size * 0.15, 0, Math.PI, 0);
        ctx.lineTo(x + width * 0.85, y + size * 0.15);
        ctx.fill();
        ctx.stroke();
        // Middle ellipses
        ctx.beginPath();
        ctx.ellipse(centerX, y + size * 0.35, size * 0.35, size * 0.1, 0, 0, Math.PI);
        ctx.stroke();
        ctx.beginPath();
        ctx.ellipse(centerX, y + size * 0.55, size * 0.35, size * 0.1, 0, 0, Math.PI);
        ctx.stroke();
        break;

      case 'webserver':
        // Web server: server with globe
        ctx.fillRect(x + width * 0.15, y + height * 0.35, width * 0.7, height * 0.5);
        ctx.strokeRect(x + width * 0.15, y + height * 0.35, width * 0.7, height * 0.5);
        // Globe icon
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.15, size * 0.12, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.ellipse(centerX, y + height * 0.15, size * 0.04, size * 0.12, 0, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.12, y + height * 0.15);
        ctx.lineTo(centerX + size * 0.12, y + height * 0.15);
        ctx.stroke();
        break;

      case 'pc':
        // PC: monitor and base
        ctx.fillRect(x + width * 0.15, y + height * 0.1, width * 0.7, height * 0.5);
        ctx.strokeRect(x + width * 0.15, y + height * 0.1, width * 0.7, height * 0.5);
        // Screen
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.2, y + height * 0.15, width * 0.6, height * 0.4);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Stand
        ctx.fillRect(x + width * 0.4, y + height * 0.6, width * 0.2, height * 0.15);
        ctx.strokeRect(x + width * 0.4, y + height * 0.6, width * 0.2, height * 0.15);
        // Base
        ctx.fillRect(x + width * 0.25, y + height * 0.75, width * 0.5, height * 0.1);
        ctx.strokeRect(x + width * 0.25, y + height * 0.75, width * 0.5, height * 0.1);
        break;

      case 'laptop':
        // Laptop: screen and keyboard
        ctx.fillRect(x + width * 0.1, y + height * 0.1, width * 0.8, height * 0.5);
        ctx.strokeRect(x + width * 0.1, y + height * 0.1, width * 0.8, height * 0.5);
        // Keyboard area (trapezoid)
        ctx.beginPath();
        ctx.moveTo(x + width * 0.05, y + height * 0.9);
        ctx.lineTo(x + width * 0.1, y + height * 0.6);
        ctx.lineTo(x + width * 0.9, y + height * 0.6);
        ctx.lineTo(x + width * 0.95, y + height * 0.9);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
        break;

      case 'mobile':
        // Mobile: phone shape
        const radius = size * 0.08;
        ctx.beginPath();
        ctx.roundRect(x + width * 0.3, y + height * 0.05, width * 0.4, height * 0.9, radius);
        ctx.fill();
        ctx.stroke();
        // Screen
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.33, y + height * 0.12, width * 0.34, height * 0.7);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Home button
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.88, size * 0.04, 0, Math.PI * 2);
        ctx.stroke();
        break;

      case 'printer':
        // Printer
        ctx.fillRect(x + width * 0.1, y + height * 0.35, width * 0.8, height * 0.4);
        ctx.strokeRect(x + width * 0.1, y + height * 0.35, width * 0.8, height * 0.4);
        // Paper tray (top)
        ctx.fillRect(x + width * 0.2, y + height * 0.15, width * 0.6, height * 0.2);
        ctx.strokeRect(x + width * 0.2, y + height * 0.15, width * 0.6, height * 0.2);
        // Paper output (bottom)
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(x + width * 0.25, y + height * 0.75, width * 0.5, height * 0.15);
        ctx.strokeRect(x + width * 0.25, y + height * 0.75, width * 0.5, height * 0.15);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'cloud':
        // Cloud shape
        ctx.beginPath();
        ctx.arc(centerX - size * 0.15, centerY, size * 0.2, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.15, centerY, size * 0.2, 0, Math.PI * 2);
        ctx.arc(centerX, centerY - size * 0.12, size * 0.22, 0, Math.PI * 2);
        ctx.fill();
        ctx.beginPath();
        ctx.arc(centerX - size * 0.15, centerY, size * 0.2, Math.PI * 0.5, Math.PI * 1.5);
        ctx.arc(centerX, centerY - size * 0.12, size * 0.22, Math.PI * 1.1, Math.PI * 1.9);
        ctx.arc(centerX + size * 0.15, centerY, size * 0.2, -Math.PI * 0.5, Math.PI * 0.5);
        ctx.arc(centerX, centerY + size * 0.08, size * 0.35, 0.3, Math.PI - 0.3);
        ctx.stroke();
        break;

      case 'internet':
        // Internet: globe with grid
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        // Latitude lines
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, size * 0.35, size * 0.12, 0, 0, Math.PI * 2);
        ctx.stroke();
        // Longitude lines
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, size * 0.12, size * 0.35, 0, 0, Math.PI * 2);
        ctx.stroke();
        // Equator
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.35, centerY);
        ctx.lineTo(centerX + size * 0.35, centerY);
        ctx.stroke();
        break;

      // === NEW SYMBOLS ===
      
      case 'vpn':
        // VPN: Shield with lock
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.lineTo(x + width * 0.15, y + height * 0.25);
        ctx.lineTo(x + width * 0.15, y + height * 0.6);
        ctx.quadraticCurveTo(centerX, y + height * 0.95, x + width * 0.85, y + height * 0.6);
        ctx.lineTo(x + width * 0.85, y + height * 0.25);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
        // Lock icon
        ctx.beginPath();
        ctx.arc(centerX, centerY - size * 0.05, size * 0.1, Math.PI, 0);
        ctx.stroke();
        ctx.fillRect(centerX - size * 0.12, centerY, size * 0.24, size * 0.18);
        ctx.strokeRect(centerX - size * 0.12, centerY, size * 0.24, size * 0.18);
        break;

      case 'loadbalancer':
        // Load Balancer: box with arrows
        ctx.fillRect(x + width * 0.25, y + height * 0.35, width * 0.5, height * 0.3);
        ctx.strokeRect(x + width * 0.25, y + height * 0.35, width * 0.5, height * 0.3);
        // Input arrow
        ctx.beginPath();
        ctx.moveTo(x + width * 0.1, centerY);
        ctx.lineTo(x + width * 0.25, centerY);
        ctx.stroke();
        // Output arrows
        for (let i = 0; i < 3; i++) {
          const outY = y + height * 0.3 + i * height * 0.2;
          ctx.beginPath();
          ctx.moveTo(x + width * 0.75, centerY);
          ctx.lineTo(x + width * 0.9, outY);
          ctx.stroke();
        }
        break;

      case 'lock':
        // Lock/Encryption
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.3, size * 0.15, Math.PI, 0);
        ctx.stroke();
        ctx.fillRect(x + width * 0.25, y + height * 0.4, width * 0.5, height * 0.45);
        ctx.strokeRect(x + width * 0.25, y + height * 0.4, width * 0.5, height * 0.45);
        // Keyhole
        ctx.fillStyle = stroke_color || '#3b82f6';
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.55, size * 0.06, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillRect(centerX - size * 0.03, y + height * 0.6, size * 0.06, size * 0.1);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'key':
        // Key/Auth
        ctx.beginPath();
        ctx.arc(x + width * 0.25, centerY, size * 0.15, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.4, centerY);
        ctx.lineTo(x + width * 0.85, centerY);
        ctx.lineTo(x + width * 0.85, centerY + size * 0.1);
        ctx.moveTo(x + width * 0.7, centerY);
        ctx.lineTo(x + width * 0.7, centerY + size * 0.08);
        ctx.stroke();
        break;

      case 'bug':
        // Bug/Vulnerability
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, size * 0.25, size * 0.3, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        // Bug legs
        for (let i = -1; i <= 1; i++) {
          ctx.beginPath();
          ctx.moveTo(centerX - size * 0.25, centerY + i * size * 0.15);
          ctx.lineTo(centerX - size * 0.4, centerY + i * size * 0.2);
          ctx.moveTo(centerX + size * 0.25, centerY + i * size * 0.15);
          ctx.lineTo(centerX + size * 0.4, centerY + i * size * 0.2);
          ctx.stroke();
        }
        // Antennae
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.1, centerY - size * 0.3);
        ctx.lineTo(centerX - size * 0.15, centerY - size * 0.4);
        ctx.moveTo(centerX + size * 0.1, centerY - size * 0.3);
        ctx.lineTo(centerX + size * 0.15, centerY - size * 0.4);
        ctx.stroke();
        break;

      case 'api':
        // API Server
        ctx.fillRect(x + width * 0.15, y + height * 0.2, width * 0.7, height * 0.6);
        ctx.strokeRect(x + width * 0.15, y + height * 0.2, width * 0.7, height * 0.6);
        // API text
        ctx.fillStyle = stroke_color || '#3b82f6';
        ctx.font = `bold ${size * 0.2}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('API', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'nodejs':
        // Node.js: hexagon with N
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const angle = (i / 6) * Math.PI * 2 - Math.PI / 2;
          const px = centerX + Math.cos(angle) * size * 0.35;
          const py = centerY + Math.sin(angle) * size * 0.35;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fillStyle = '#68a063';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('N', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'php':
        // PHP: ellipse with PHP
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, size * 0.4, size * 0.25, 0, 0, Math.PI * 2);
        ctx.fillStyle = '#777bb3';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.18}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('PHP', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'python':
        // Python: two intertwined snakes (simplified)
        ctx.beginPath();
        ctx.arc(centerX - size * 0.1, centerY - size * 0.15, size * 0.2, Math.PI, 0);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(centerX + size * 0.1, centerY + size * 0.15, size * 0.2, 0, Math.PI);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.1, centerY - size * 0.15);
        ctx.lineTo(centerX - size * 0.1, centerY + size * 0.35);
        ctx.moveTo(centerX + size * 0.1, centerY + size * 0.15);
        ctx.lineTo(centerX + size * 0.1, centerY - size * 0.35);
        ctx.stroke();
        // Eyes
        ctx.fillStyle = stroke_color || '#3b82f6';
        ctx.beginPath();
        ctx.arc(centerX - size * 0.15, centerY - size * 0.25, size * 0.04, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.15, centerY + size * 0.25, size * 0.04, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'java':
        // Java: coffee cup
        ctx.beginPath();
        ctx.moveTo(x + width * 0.25, y + height * 0.3);
        ctx.lineTo(x + width * 0.3, y + height * 0.8);
        ctx.lineTo(x + width * 0.6, y + height * 0.8);
        ctx.lineTo(x + width * 0.65, y + height * 0.3);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
        // Handle
        ctx.beginPath();
        ctx.arc(x + width * 0.7, centerY, size * 0.12, -Math.PI / 2, Math.PI / 2);
        ctx.stroke();
        // Steam
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.08, y + height * 0.2);
        ctx.quadraticCurveTo(centerX - size * 0.12, y + height * 0.1, centerX - size * 0.08, y + height * 0.05);
        ctx.moveTo(centerX + size * 0.08, y + height * 0.2);
        ctx.quadraticCurveTo(centerX + size * 0.12, y + height * 0.1, centerX + size * 0.08, y + height * 0.05);
        ctx.stroke();
        break;

      case 'docker':
        // Docker: whale with containers
        ctx.beginPath();
        ctx.ellipse(centerX, centerY + size * 0.1, size * 0.35, size * 0.2, 0, 0, Math.PI * 2);
        ctx.fillStyle = '#2496ed';
        ctx.fill();
        ctx.stroke();
        // Containers on top
        ctx.fillStyle = '#ffffff';
        for (let row = 0; row < 2; row++) {
          for (let col = 0; col < 3; col++) {
            const bx = centerX - size * 0.2 + col * size * 0.14;
            const by = centerY - size * 0.15 - row * size * 0.12;
            ctx.fillRect(bx, by, size * 0.1, size * 0.08);
            ctx.strokeRect(bx, by, size * 0.1, size * 0.08);
          }
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'kubernetes':
        // Kubernetes: wheel/helm
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.3, 0, Math.PI * 2);
        ctx.fillStyle = '#326ce5';
        ctx.fill();
        ctx.stroke();
        // Spokes
        ctx.strokeStyle = '#ffffff';
        for (let i = 0; i < 7; i++) {
          const angle = (i / 7) * Math.PI * 2;
          ctx.beginPath();
          ctx.moveTo(centerX, centerY);
          ctx.lineTo(centerX + Math.cos(angle) * size * 0.25, centerY + Math.sin(angle) * size * 0.25);
          ctx.stroke();
        }
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'mysql':
      case 'postgresql':
      case 'sql':
        // SQL Database: cylinder with table icon
        ctx.beginPath();
        ctx.ellipse(centerX, y + size * 0.15, size * 0.35, size * 0.15, 0, 0, Math.PI * 2);
        ctx.fillStyle = symbol_type === 'mysql' ? '#00758f' : symbol_type === 'postgresql' ? '#336791' : fill_color || 'rgba(59, 130, 246, 0.2)';
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + size * 0.15);
        ctx.lineTo(x + width * 0.15, y + size * 0.75);
        ctx.ellipse(centerX, y + size * 0.75, size * 0.35, size * 0.15, 0, Math.PI, 0);
        ctx.lineTo(x + width * 0.85, y + size * 0.15);
        ctx.fill();
        ctx.stroke();
        // Table lines
        ctx.strokeStyle = '#ffffff';
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.2, centerY);
        ctx.lineTo(centerX + size * 0.2, centerY);
        ctx.moveTo(centerX - size * 0.2, centerY + size * 0.15);
        ctx.lineTo(centerX + size * 0.2, centerY + size * 0.15);
        ctx.moveTo(centerX, centerY - size * 0.1);
        ctx.lineTo(centerX, centerY + size * 0.25);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'mongodb':
        // MongoDB: leaf shape
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.quadraticCurveTo(x + width * 0.15, centerY, centerX, y + height * 0.9);
        ctx.quadraticCurveTo(x + width * 0.85, centerY, centerX, y + height * 0.1);
        ctx.fillStyle = '#4db33d';
        ctx.fill();
        ctx.stroke();
        // Stem
        ctx.strokeStyle = '#ffffff';
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.3);
        ctx.lineTo(centerX, y + height * 0.7);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'redis':
        // Redis: diamond/cube shape
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.15);
        ctx.lineTo(x + width * 0.85, centerY);
        ctx.lineTo(centerX, y + height * 0.85);
        ctx.lineTo(x + width * 0.15, centerY);
        ctx.closePath();
        ctx.fillStyle = '#dc382d';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'react':
        // React: atom symbol
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.08, 0, Math.PI * 2);
        ctx.fillStyle = '#61dafb';
        ctx.fill();
        // Orbits
        for (let i = 0; i < 3; i++) {
          ctx.save();
          ctx.translate(centerX, centerY);
          ctx.rotate((i / 3) * Math.PI);
          ctx.beginPath();
          ctx.ellipse(0, 0, size * 0.35, size * 0.12, 0, 0, Math.PI * 2);
          ctx.strokeStyle = '#61dafb';
          ctx.stroke();
          ctx.restore();
        }
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'vue':
        // Vue: V shape
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + height * 0.2);
        ctx.lineTo(centerX, y + height * 0.8);
        ctx.lineTo(x + width * 0.85, y + height * 0.2);
        ctx.lineTo(x + width * 0.7, y + height * 0.2);
        ctx.lineTo(centerX, y + height * 0.6);
        ctx.lineTo(x + width * 0.3, y + height * 0.2);
        ctx.closePath();
        ctx.fillStyle = '#42b883';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'angular':
        // Angular: shield with A
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.lineTo(x + width * 0.15, y + height * 0.25);
        ctx.lineTo(x + width * 0.2, y + height * 0.85);
        ctx.lineTo(centerX, y + height * 0.95);
        ctx.lineTo(x + width * 0.8, y + height * 0.85);
        ctx.lineTo(x + width * 0.85, y + height * 0.25);
        ctx.closePath();
        ctx.fillStyle = '#dd0031';
        ctx.fill();
        ctx.stroke();
        // A letter
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.3}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('A', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'vite':
        // Vite: lightning bolt
        ctx.beginPath();
        ctx.moveTo(centerX + size * 0.15, y + height * 0.1);
        ctx.lineTo(centerX - size * 0.2, centerY);
        ctx.lineTo(centerX, centerY);
        ctx.lineTo(centerX - size * 0.15, y + height * 0.9);
        ctx.lineTo(centerX + size * 0.2, centerY);
        ctx.lineTo(centerX, centerY);
        ctx.closePath();
        ctx.fillStyle = '#646cff';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'nextjs':
        // Next.js: N in circle
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#000000';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.3}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('N', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'typescript':
        // TypeScript: TS box
        ctx.fillRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#3178c6';
        ctx.fill();
        ctx.strokeRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('TS', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'javascript':
        // JavaScript: JS box
        ctx.fillStyle = '#f7df1e';
        ctx.fillRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.strokeRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#000000';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('JS', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'html':
        // HTML: shield with 5
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + height * 0.1);
        ctx.lineTo(x + width * 0.2, y + height * 0.85);
        ctx.lineTo(centerX, y + height * 0.95);
        ctx.lineTo(x + width * 0.8, y + height * 0.85);
        ctx.lineTo(x + width * 0.85, y + height * 0.1);
        ctx.closePath();
        ctx.fillStyle = '#e34f26';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.2}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('HTML', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'css':
        // CSS: shield with 3
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + height * 0.1);
        ctx.lineTo(x + width * 0.2, y + height * 0.85);
        ctx.lineTo(centerX, y + height * 0.95);
        ctx.lineTo(x + width * 0.8, y + height * 0.85);
        ctx.lineTo(x + width * 0.85, y + height * 0.1);
        ctx.closePath();
        ctx.fillStyle = '#264de4';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.2}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('CSS', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'iphone':
        // iPhone: rounded rectangle with notch
        const iphoneRadius = size * 0.1;
        ctx.beginPath();
        ctx.roundRect(x + width * 0.25, y + height * 0.05, width * 0.5, height * 0.9, iphoneRadius);
        ctx.fill();
        ctx.stroke();
        // Screen
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.28, y + height * 0.1, width * 0.44, height * 0.75);
        // Notch
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        ctx.beginPath();
        ctx.roundRect(x + width * 0.38, y + height * 0.1, width * 0.24, height * 0.04, 3);
        ctx.fill();
        break;

      case 'ios':
        // iOS/Apple: apple logo (simplified)
        ctx.beginPath();
        ctx.arc(centerX, centerY + size * 0.05, size * 0.28, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        // Bite
        ctx.fillStyle = '#1e1e2e';
        ctx.beginPath();
        ctx.arc(centerX + size * 0.35, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Leaf
        ctx.beginPath();
        ctx.ellipse(centerX + size * 0.08, centerY - size * 0.28, size * 0.08, size * 0.12, Math.PI / 4, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        break;

      case 'android':
        // Android: robot head
        ctx.beginPath();
        ctx.arc(centerX, centerY + size * 0.05, size * 0.3, Math.PI, 0);
        ctx.lineTo(centerX + size * 0.3, centerY + size * 0.25);
        ctx.lineTo(centerX - size * 0.3, centerY + size * 0.25);
        ctx.closePath();
        ctx.fillStyle = '#3ddc84';
        ctx.fill();
        ctx.stroke();
        // Eyes
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(centerX - size * 0.12, centerY, size * 0.05, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.12, centerY, size * 0.05, 0, Math.PI * 2);
        ctx.fill();
        // Antennae
        ctx.strokeStyle = '#3ddc84';
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.15, centerY - size * 0.25);
        ctx.lineTo(centerX - size * 0.22, centerY - size * 0.4);
        ctx.moveTo(centerX + size * 0.15, centerY - size * 0.25);
        ctx.lineTo(centerX + size * 0.22, centerY - size * 0.4);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'tablet':
        // Tablet/iPad
        const tabletRadius = size * 0.06;
        ctx.beginPath();
        ctx.roundRect(x + width * 0.1, y + height * 0.1, width * 0.8, height * 0.8, tabletRadius);
        ctx.fill();
        ctx.stroke();
        // Screen
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.65);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Home button
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.85, size * 0.04, 0, Math.PI * 2);
        ctx.stroke();
        break;

      case 'smartwatch':
        // Smart Watch
        ctx.beginPath();
        ctx.roundRect(x + width * 0.25, y + height * 0.2, width * 0.5, height * 0.6, size * 0.08);
        ctx.fill();
        ctx.stroke();
        // Screen
        ctx.fillStyle = '#1e1e2e';
        ctx.roundRect(x + width * 0.3, y + height * 0.25, width * 0.4, height * 0.5, size * 0.05);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Band top and bottom
        ctx.fillRect(x + width * 0.35, y + height * 0.05, width * 0.3, height * 0.15);
        ctx.fillRect(x + width * 0.35, y + height * 0.8, width * 0.3, height * 0.15);
        break;

      case 'tv':
        // TV/Display
        ctx.fillRect(x + width * 0.1, y + height * 0.15, width * 0.8, height * 0.55);
        ctx.strokeRect(x + width * 0.1, y + height * 0.15, width * 0.8, height * 0.55);
        // Screen
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.13, y + height * 0.18, width * 0.74, height * 0.49);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Stand
        ctx.beginPath();
        ctx.moveTo(x + width * 0.35, y + height * 0.7);
        ctx.lineTo(x + width * 0.2, y + height * 0.85);
        ctx.moveTo(x + width * 0.65, y + height * 0.7);
        ctx.lineTo(x + width * 0.8, y + height * 0.85);
        ctx.stroke();
        break;

      case 'speaker':
        // Smart Speaker
        ctx.beginPath();
        ctx.ellipse(centerX, y + height * 0.85, size * 0.25, size * 0.08, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.25, y + height * 0.85);
        ctx.lineTo(x + width * 0.3, y + height * 0.25);
        ctx.arc(centerX, y + height * 0.25, size * 0.2, Math.PI, 0);
        ctx.lineTo(x + width * 0.75, y + height * 0.85);
        ctx.fill();
        ctx.stroke();
        // Sound waves
        for (let i = 1; i <= 2; i++) {
          ctx.beginPath();
          ctx.arc(centerX, y + height * 0.35, size * 0.08 * i, -Math.PI * 0.3, Math.PI * 0.3);
          ctx.stroke();
        }
        break;

      case 'cpu':
        // CPU/Processor
        ctx.fillRect(x + width * 0.2, y + height * 0.2, width * 0.6, height * 0.6);
        ctx.strokeRect(x + width * 0.2, y + height * 0.2, width * 0.6, height * 0.6);
        // Pins
        for (let i = 0; i < 4; i++) {
          const pinOffset = width * 0.25 + i * width * 0.15;
          // Top pins
          ctx.fillRect(x + pinOffset, y + height * 0.1, width * 0.06, height * 0.1);
          // Bottom pins
          ctx.fillRect(x + pinOffset, y + height * 0.8, width * 0.06, height * 0.1);
          // Left pins
          ctx.fillRect(x + width * 0.1, y + height * 0.25 + i * height * 0.15, width * 0.1, height * 0.06);
          // Right pins
          ctx.fillRect(x + width * 0.8, y + height * 0.25 + i * height * 0.15, width * 0.1, height * 0.06);
        }
        // Inner square
        ctx.strokeRect(x + width * 0.3, y + height * 0.3, width * 0.4, height * 0.4);
        break;

      case 'memory':
        // Memory/RAM stick
        ctx.fillRect(x + width * 0.05, y + height * 0.35, width * 0.9, height * 0.3);
        ctx.strokeRect(x + width * 0.05, y + height * 0.35, width * 0.9, height * 0.3);
        // Chips
        for (let i = 0; i < 4; i++) {
          ctx.fillStyle = '#1e1e2e';
          ctx.fillRect(x + width * 0.12 + i * width * 0.2, y + height * 0.4, width * 0.12, height * 0.2);
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        // Notch
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.4, y + height * 0.65, width * 0.1, height * 0.08);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'usb':
        // USB Device
        ctx.fillRect(x + width * 0.3, y + height * 0.2, width * 0.4, height * 0.6);
        ctx.strokeRect(x + width * 0.3, y + height * 0.2, width * 0.4, height * 0.6);
        // USB connector
        ctx.fillRect(x + width * 0.35, y + height * 0.8, width * 0.3, height * 0.15);
        ctx.strokeRect(x + width * 0.35, y + height * 0.8, width * 0.3, height * 0.15);
        // USB symbol
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.3);
        ctx.lineTo(centerX, y + height * 0.6);
        ctx.moveTo(centerX - size * 0.1, y + height * 0.4);
        ctx.lineTo(centerX, y + height * 0.3);
        ctx.lineTo(centerX + size * 0.1, y + height * 0.4);
        ctx.stroke();
        break;

      case 'bluetooth':
        // Bluetooth symbol
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.lineTo(centerX, y + height * 0.9);
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.lineTo(centerX + size * 0.2, y + height * 0.3);
        ctx.lineTo(centerX - size * 0.2, y + height * 0.5);
        ctx.moveTo(centerX, y + height * 0.9);
        ctx.lineTo(centerX + size * 0.2, y + height * 0.7);
        ctx.lineTo(centerX - size * 0.2, y + height * 0.5);
        ctx.strokeStyle = '#0082fc';
        ctx.lineWidth = stroke_width + 1;
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        break;

      case 'keyboard':
        // Keyboard
        ctx.fillRect(x + width * 0.05, y + height * 0.3, width * 0.9, height * 0.4);
        ctx.strokeRect(x + width * 0.05, y + height * 0.3, width * 0.9, height * 0.4);
        // Keys
        for (let row = 0; row < 3; row++) {
          for (let col = 0; col < 8; col++) {
            ctx.strokeRect(
              x + width * 0.08 + col * width * 0.1,
              y + height * 0.35 + row * height * 0.1,
              width * 0.08,
              height * 0.08
            );
          }
        }
        break;

      case 'mouse':
        // Mouse
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, size * 0.2, size * 0.35, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        // Buttons
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.15);
        ctx.lineTo(centerX, centerY);
        ctx.stroke();
        // Scroll wheel
        ctx.beginPath();
        ctx.ellipse(centerX, y + height * 0.35, size * 0.04, size * 0.08, 0, 0, Math.PI * 2);
        ctx.stroke();
        break;

      case 'aws':
        // AWS: smile arrow
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#ff9900';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.2}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('AWS', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'azure':
        // Azure: slanted rectangle
        ctx.beginPath();
        ctx.moveTo(x + width * 0.2, y + height * 0.2);
        ctx.lineTo(x + width * 0.5, y + height * 0.2);
        ctx.lineTo(x + width * 0.8, y + height * 0.8);
        ctx.lineTo(x + width * 0.5, y + height * 0.8);
        ctx.closePath();
        ctx.fillStyle = '#0078d4';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'gcp':
        // GCP: colored hexagon
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const angle = (i / 6) * Math.PI * 2 - Math.PI / 2;
          const px = centerX + Math.cos(angle) * size * 0.35;
          const py = centerY + Math.sin(angle) * size * 0.35;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fillStyle = '#4285f4';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.15}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('GCP', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'wireless_ap':
        // Wireless AP (same as wireless)
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.7);
        ctx.lineTo(centerX, y + height * 0.3);
        ctx.stroke();
        for (let i = 1; i <= 3; i++) {
          ctx.beginPath();
          ctx.arc(centerX, y + height * 0.3, size * 0.1 * i, -Math.PI * 0.8, -Math.PI * 0.2);
          ctx.stroke();
        }
        ctx.beginPath();
        ctx.ellipse(centerX, y + height * 0.75, size * 0.2, size * 0.08, 0, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        break;

      case 'web_server':
        // Web server (same as webserver)
        ctx.fillRect(x + width * 0.15, y + height * 0.35, width * 0.7, height * 0.5);
        ctx.strokeRect(x + width * 0.15, y + height * 0.35, width * 0.7, height * 0.5);
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.15, size * 0.12, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.ellipse(centerX, y + height * 0.15, size * 0.04, size * 0.12, 0, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.12, y + height * 0.15);
        ctx.lineTo(centerX + size * 0.12, y + height * 0.15);
        ctx.stroke();
        break;

      // === CLOUD PROVIDERS ===
      case 'alibaba':
        // Alibaba Cloud: orange circle with A
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#ff6a00';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('阿里', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'huawei':
        // Huawei Cloud: red flower petal shape
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#cf0a2c';
        ctx.fill();
        ctx.stroke();
        // Petal pattern
        ctx.fillStyle = '#ffffff';
        for (let i = 0; i < 8; i++) {
          const angle = (i / 8) * Math.PI * 2;
          ctx.beginPath();
          ctx.ellipse(
            centerX + Math.cos(angle) * size * 0.15,
            centerY + Math.sin(angle) * size * 0.15,
            size * 0.08, size * 0.12, angle, 0, Math.PI * 2
          );
          ctx.fill();
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'yandex':
        // Yandex Cloud: Y in red circle
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#fc3f1d';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.35}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('Я', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'oracle':
        // Oracle Cloud: red rounded box
        ctx.beginPath();
        ctx.roundRect(x + width * 0.1, y + height * 0.25, width * 0.8, height * 0.5, size * 0.1);
        ctx.fillStyle = '#f80000';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.15}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('ORACLE', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'ibm':
        // IBM Cloud: blue stripes
        ctx.fillStyle = '#0f62fe';
        for (let i = 0; i < 8; i++) {
          if (i % 2 === 0) {
            ctx.fillRect(x + width * 0.15, y + height * 0.2 + i * height * 0.075, width * 0.7, height * 0.06);
          }
        }
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.2}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('IBM', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'digitalocean':
        // DigitalOcean: blue circle with droplet
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#0080ff';
        ctx.fill();
        ctx.stroke();
        // Droplet shape
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.25);
        ctx.quadraticCurveTo(x + width * 0.65, centerY, centerX, y + height * 0.7);
        ctx.quadraticCurveTo(x + width * 0.35, centerY, centerX, y + height * 0.25);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === CONNECTIVITY SYMBOLS ===
      case 'cellular':
        // Cellular signal bars
        ctx.fillStyle = stroke_color || '#3b82f6';
        for (let i = 0; i < 4; i++) {
          const barHeight = height * (0.2 + i * 0.2);
          const barX = x + width * 0.2 + i * width * 0.18;
          ctx.fillRect(barX, y + height * 0.85 - barHeight, width * 0.12, barHeight);
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'wifi_signal':
        // WiFi signal waves
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width + 1;
        for (let i = 1; i <= 3; i++) {
          ctx.beginPath();
          ctx.arc(centerX, y + height * 0.75, size * 0.12 * i, -Math.PI * 0.75, -Math.PI * 0.25);
          ctx.stroke();
        }
        // Dot at bottom
        ctx.fillStyle = stroke_color || '#3b82f6';
        ctx.beginPath();
        ctx.arc(centerX, y + height * 0.78, size * 0.05, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'wifi_off':
        // WiFi with X
        ctx.strokeStyle = '#6b7280';
        ctx.lineWidth = stroke_width + 1;
        for (let i = 1; i <= 3; i++) {
          ctx.beginPath();
          ctx.arc(centerX, y + height * 0.75, size * 0.12 * i, -Math.PI * 0.75, -Math.PI * 0.25);
          ctx.stroke();
        }
        // X over it
        ctx.strokeStyle = '#ef4444';
        ctx.lineWidth = stroke_width + 2;
        ctx.beginPath();
        ctx.moveTo(x + width * 0.25, y + height * 0.25);
        ctx.lineTo(x + width * 0.75, y + height * 0.75);
        ctx.moveTo(x + width * 0.75, y + height * 0.25);
        ctx.lineTo(x + width * 0.25, y + height * 0.75);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        break;

      case '4g':
        // 4G LTE badge
        ctx.beginPath();
        ctx.roundRect(x + width * 0.1, y + height * 0.25, width * 0.8, height * 0.5, size * 0.08);
        ctx.fillStyle = '#3b82f6';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.22}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('4G', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case '5g':
        // 5G badge
        ctx.beginPath();
        ctx.roundRect(x + width * 0.1, y + height * 0.25, width * 0.8, height * 0.5, size * 0.08);
        ctx.fillStyle = '#8b5cf6';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.22}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('5G', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'satellite':
        // Satellite dish
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.3, Math.PI * 0.75, Math.PI * 1.75);
        ctx.lineTo(centerX, centerY);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
        // Arm
        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(centerX + size * 0.25, centerY - size * 0.25);
        ctx.stroke();
        // LNB
        ctx.beginPath();
        ctx.arc(centerX + size * 0.25, centerY - size * 0.25, size * 0.06, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        // Signal waves
        for (let i = 1; i <= 2; i++) {
          ctx.beginPath();
          ctx.arc(centerX + size * 0.25, centerY - size * 0.25, size * 0.1 * i, -Math.PI * 0.25, Math.PI * 0.25);
          ctx.stroke();
        }
        break;

      case 'ethernet':
        // Ethernet cable connector
        ctx.fillRect(x + width * 0.25, y + height * 0.2, width * 0.5, height * 0.6);
        ctx.strokeRect(x + width * 0.25, y + height * 0.2, width * 0.5, height * 0.6);
        // Cable
        ctx.fillRect(x + width * 0.35, y + height * 0.8, width * 0.3, height * 0.15);
        // Contacts
        ctx.fillStyle = '#fbbf24';
        for (let i = 0; i < 4; i++) {
          ctx.fillRect(x + width * 0.32 + i * width * 0.1, y + height * 0.25, width * 0.06, height * 0.4);
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'gps':
        // GPS location pin
        ctx.beginPath();
        ctx.arc(centerX, centerY - size * 0.1, size * 0.2, Math.PI, 0);
        ctx.quadraticCurveTo(centerX + size * 0.2, centerY + size * 0.1, centerX, y + height * 0.85);
        ctx.quadraticCurveTo(centerX - size * 0.2, centerY + size * 0.1, centerX - size * 0.2, centerY - size * 0.1);
        ctx.fillStyle = '#ef4444';
        ctx.fill();
        ctx.stroke();
        // Inner circle
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(centerX, centerY - size * 0.1, size * 0.08, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === MORE PROGRAMMING LANGUAGES ===
      case 'go':
        // Go/Golang: gopher simplified
        ctx.beginPath();
        ctx.roundRect(x + width * 0.15, y + height * 0.2, width * 0.7, height * 0.6, size * 0.1);
        ctx.fillStyle = '#00add8';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('Go', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'rust':
        // Rust: gear cog shape
        ctx.beginPath();
        for (let i = 0; i < 12; i++) {
          const angle = (i / 12) * Math.PI * 2;
          const outerR = i % 2 === 0 ? size * 0.35 : size * 0.28;
          const px = centerX + Math.cos(angle) * outerR;
          const py = centerY + Math.sin(angle) * outerR;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fillStyle = '#dea584';
        ctx.fill();
        ctx.stroke();
        // Inner hole
        ctx.fillStyle = '#1e1e2e';
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'csharp':
        // C#: purple box
        ctx.fillRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#512bd4';
        ctx.fill();
        ctx.strokeRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('C#', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'cpp':
        // C++: blue box
        ctx.fillRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#00599c';
        ctx.fill();
        ctx.strokeRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.2}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('C++', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'ruby':
        // Ruby: red gem shape
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.15);
        ctx.lineTo(x + width * 0.8, y + height * 0.35);
        ctx.lineTo(x + width * 0.7, y + height * 0.85);
        ctx.lineTo(x + width * 0.3, y + height * 0.85);
        ctx.lineTo(x + width * 0.2, y + height * 0.35);
        ctx.closePath();
        ctx.fillStyle = '#cc342d';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'swift':
        // Swift: bird shape simplified
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#f05138';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.3}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('S', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'kotlin':
        // Kotlin: gradient triangle
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + height * 0.15);
        ctx.lineTo(x + width * 0.85, y + height * 0.15);
        ctx.lineTo(x + width * 0.15, y + height * 0.85);
        ctx.closePath();
        ctx.fillStyle = '#7f52ff';
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.15, y + height * 0.15);
        ctx.lineTo(centerX, centerY);
        ctx.lineTo(x + width * 0.15, y + height * 0.85);
        ctx.closePath();
        ctx.fillStyle = '#c711e1';
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'flutter':
        // Flutter: blue diamond
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.lineTo(x + width * 0.75, centerY);
        ctx.lineTo(centerX, y + height * 0.9);
        ctx.lineTo(x + width * 0.25, centerY);
        ctx.closePath();
        ctx.fillStyle = '#02569b';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'svelte':
        // Svelte: S in orange circle
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#ff3e00';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.35}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('S', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'graphql':
        // GraphQL: pink hexagon
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const angle = (i / 6) * Math.PI * 2 - Math.PI / 2;
          const px = centerX + Math.cos(angle) * size * 0.35;
          const py = centerY + Math.sin(angle) * size * 0.35;
          if (i === 0) ctx.moveTo(px, py);
          else ctx.lineTo(px, py);
        }
        ctx.closePath();
        ctx.fillStyle = '#e10098';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === SERVER SOFTWARE ===
      case 'linux':
        // Linux: penguin simplified
        ctx.beginPath();
        ctx.ellipse(centerX, centerY + size * 0.1, size * 0.25, size * 0.3, 0, 0, Math.PI * 2);
        ctx.fillStyle = '#1e1e2e';
        ctx.fill();
        ctx.stroke();
        // Belly
        ctx.fillStyle = '#fbbf24';
        ctx.beginPath();
        ctx.ellipse(centerX, centerY + size * 0.15, size * 0.15, size * 0.2, 0, 0, Math.PI * 2);
        ctx.fill();
        // Eyes
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(centerX - size * 0.08, centerY - size * 0.08, size * 0.06, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.08, centerY - size * 0.08, size * 0.06, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'windows_server':
        // Windows Server: window panes
        ctx.fillRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        ctx.fillStyle = '#00adef';
        ctx.fill();
        ctx.strokeRect(x + width * 0.15, y + height * 0.15, width * 0.7, height * 0.7);
        // Dividers
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = stroke_width + 1;
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.15);
        ctx.lineTo(centerX, y + height * 0.85);
        ctx.moveTo(x + width * 0.15, centerY);
        ctx.lineTo(x + width * 0.85, centerY);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'nginx':
        // Nginx: green N
        ctx.beginPath();
        ctx.roundRect(x + width * 0.15, y + height * 0.2, width * 0.7, height * 0.6, size * 0.08);
        ctx.fillStyle = '#009639';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('Nx', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'apache':
        // Apache: feather simplified
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.quadraticCurveTo(x + width * 0.8, centerY, centerX, y + height * 0.9);
        ctx.quadraticCurveTo(x + width * 0.2, centerY, centerX, y + height * 0.1);
        ctx.fillStyle = '#d22128';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === MORE DATABASES ===
      case 'elasticsearch':
        // Elasticsearch: magnifying glass + bars
        ctx.beginPath();
        ctx.arc(centerX - size * 0.08, centerY - size * 0.05, size * 0.2, 0, Math.PI * 2);
        ctx.fillStyle = '#fed10a';
        ctx.fill();
        ctx.stroke();
        // Handle
        ctx.beginPath();
        ctx.moveTo(centerX + size * 0.08, centerY + size * 0.12);
        ctx.lineTo(centerX + size * 0.25, centerY + size * 0.3);
        ctx.lineWidth = stroke_width + 2;
        ctx.stroke();
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'cassandra':
        // Cassandra: eye shape
        ctx.beginPath();
        ctx.ellipse(centerX, centerY, size * 0.35, size * 0.2, 0, 0, Math.PI * 2);
        ctx.fillStyle = '#1287b1';
        ctx.fill();
        ctx.stroke();
        // Pupil
        ctx.fillStyle = '#ffffff';
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.1, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'sqlite':
        // SQLite: feather with database
        ctx.beginPath();
        ctx.ellipse(centerX, y + size * 0.15, size * 0.3, size * 0.12, 0, 0, Math.PI * 2);
        ctx.fillStyle = '#003b57';
        ctx.fill();
        ctx.stroke();
        ctx.beginPath();
        ctx.moveTo(x + width * 0.2, y + size * 0.15);
        ctx.lineTo(x + width * 0.2, y + size * 0.75);
        ctx.ellipse(centerX, y + size * 0.75, size * 0.3, size * 0.12, 0, Math.PI, 0);
        ctx.lineTo(x + width * 0.8, y + size * 0.15);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.12}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('SQLite', centerX, centerY + size * 0.1);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'firebase':
        // Firebase: flame shape
        ctx.beginPath();
        ctx.moveTo(centerX, y + height * 0.1);
        ctx.quadraticCurveTo(x + width * 0.65, y + height * 0.25, x + width * 0.7, centerY);
        ctx.quadraticCurveTo(x + width * 0.75, y + height * 0.7, centerX, y + height * 0.9);
        ctx.quadraticCurveTo(x + width * 0.25, y + height * 0.7, x + width * 0.3, centerY);
        ctx.quadraticCurveTo(x + width * 0.35, y + height * 0.25, centerX, y + height * 0.1);
        ctx.fillStyle = '#ffca28';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === MORE HARDWARE ===
      case 'ssd':
        // SSD Storage
        ctx.fillRect(x + width * 0.1, y + height * 0.25, width * 0.8, height * 0.5);
        ctx.strokeRect(x + width * 0.1, y + height * 0.25, width * 0.8, height * 0.5);
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.15, y + height * 0.3, width * 0.4, height * 0.15);
        ctx.fillStyle = '#22c55e';
        ctx.beginPath();
        ctx.arc(x + width * 0.75, y + height * 0.38, size * 0.04, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'gpu':
        // GPU: graphics card
        ctx.fillRect(x + width * 0.05, y + height * 0.3, width * 0.9, height * 0.4);
        ctx.strokeRect(x + width * 0.05, y + height * 0.3, width * 0.9, height * 0.4);
        // Fan
        ctx.beginPath();
        ctx.arc(x + width * 0.3, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(x + width * 0.6, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.stroke();
        // Connectors
        ctx.fillStyle = '#fbbf24';
        ctx.fillRect(x + width * 0.1, y + height * 0.7, width * 0.25, height * 0.1);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'rack':
        // Server Rack
        ctx.strokeRect(x + width * 0.15, y + height * 0.05, width * 0.7, height * 0.9);
        for (let i = 0; i < 4; i++) {
          const rackY = y + height * 0.1 + i * height * 0.2;
          ctx.fillRect(x + width * 0.2, rackY, width * 0.6, height * 0.15);
          ctx.strokeRect(x + width * 0.2, rackY, width * 0.6, height * 0.15);
          ctx.fillStyle = '#22c55e';
          ctx.beginPath();
          ctx.arc(x + width * 0.27, rackY + height * 0.075, 3, 0, Math.PI * 2);
          ctx.fill();
          ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        }
        break;

      case 'nas':
        // NAS Storage
        ctx.fillRect(x + width * 0.15, y + height * 0.1, width * 0.7, height * 0.8);
        ctx.strokeRect(x + width * 0.15, y + height * 0.1, width * 0.7, height * 0.8);
        // Drive bays
        for (let i = 0; i < 4; i++) {
          ctx.strokeRect(x + width * 0.2, y + height * 0.15 + i * height * 0.18, width * 0.6, height * 0.15);
        }
        // LED
        ctx.fillStyle = '#3b82f6';
        ctx.beginPath();
        ctx.arc(x + width * 0.75, y + height * 0.85, size * 0.04, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === MESSAGE QUEUES ===
      case 'kafka':
        // Kafka: K in black circle
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#231f20';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.3}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('K', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'rabbitmq':
        // RabbitMQ: orange rabbit
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#ff6600';
        ctx.fill();
        ctx.stroke();
        // Ears
        ctx.beginPath();
        ctx.ellipse(centerX - size * 0.12, centerY - size * 0.35, size * 0.06, size * 0.15, -0.2, 0, Math.PI * 2);
        ctx.ellipse(centerX + size * 0.12, centerY - size * 0.35, size * 0.06, size * 0.15, 0.2, 0, Math.PI * 2);
        ctx.fillStyle = '#ff6600';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === MONITORING ===
      case 'grafana':
        // Grafana: orange G
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#f46800';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.3}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('G', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'prometheus':
        // Prometheus: flame torch
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fillStyle = '#e6522c';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.25}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('P', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === GAMING/VR ===
      case 'gamepad':
        // Gamepad controller
        ctx.beginPath();
        ctx.roundRect(x + width * 0.1, y + height * 0.3, width * 0.8, height * 0.4, size * 0.15);
        ctx.fill();
        ctx.stroke();
        // D-pad
        ctx.fillStyle = '#1e1e2e';
        ctx.fillRect(x + width * 0.2, centerY - size * 0.05, size * 0.12, size * 0.1);
        ctx.fillRect(x + width * 0.18, centerY - size * 0.03, size * 0.16, size * 0.06);
        // Buttons
        ctx.fillStyle = '#ef4444';
        ctx.beginPath();
        ctx.arc(x + width * 0.72, centerY - size * 0.05, size * 0.04, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#22c55e';
        ctx.beginPath();
        ctx.arc(x + width * 0.78, centerY + size * 0.02, size * 0.04, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'vr_headset':
        // VR Headset
        ctx.beginPath();
        ctx.roundRect(x + width * 0.1, y + height * 0.25, width * 0.8, height * 0.5, size * 0.12);
        ctx.fill();
        ctx.stroke();
        // Lenses
        ctx.fillStyle = '#1e1e2e';
        ctx.beginPath();
        ctx.arc(centerX - size * 0.15, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.15, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.fill();
        // Strap
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.beginPath();
        ctx.moveTo(x + width * 0.1, centerY);
        ctx.lineTo(x, centerY - size * 0.1);
        ctx.moveTo(x + width * 0.9, centerY);
        ctx.lineTo(x + width, centerY - size * 0.1);
        ctx.stroke();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      // === AI/LLM PROVIDERS ===
      case 'openai':
        // OpenAI: black circle with spiral
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#000000';
        ctx.fill();
        ctx.stroke();
        // Spiral/hexagon pattern
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = stroke_width + 1;
        ctx.beginPath();
        for (let i = 0; i < 6; i++) {
          const angle = (i / 6) * Math.PI * 2 - Math.PI / 2;
          const nextAngle = ((i + 1) / 6) * Math.PI * 2 - Math.PI / 2;
          ctx.moveTo(centerX + Math.cos(angle) * size * 0.25, centerY + Math.sin(angle) * size * 0.25);
          ctx.lineTo(centerX + Math.cos(nextAngle) * size * 0.15, centerY + Math.sin(nextAngle) * size * 0.15);
        }
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'anthropic':
        // Anthropic: tan/brown circle with A
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#d4a574';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#1e1e2e';
        ctx.font = `bold ${size * 0.35}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('A', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'google_ai':
        // Google AI/Gemini: multicolored star
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#4285f4';
        ctx.fill();
        ctx.stroke();
        // Star/sparkle
        const colors = ['#ea4335', '#fbbc04', '#34a853', '#4285f4'];
        for (let i = 0; i < 4; i++) {
          const angle = (i / 4) * Math.PI * 2 - Math.PI / 2;
          ctx.fillStyle = colors[i];
          ctx.beginPath();
          ctx.moveTo(centerX, centerY);
          ctx.lineTo(centerX + Math.cos(angle - 0.3) * size * 0.15, centerY + Math.sin(angle - 0.3) * size * 0.15);
          ctx.lineTo(centerX + Math.cos(angle) * size * 0.28, centerY + Math.sin(angle) * size * 0.28);
          ctx.lineTo(centerX + Math.cos(angle + 0.3) * size * 0.15, centerY + Math.sin(angle + 0.3) * size * 0.15);
          ctx.closePath();
          ctx.fill();
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'meta_ai':
        // Meta AI/Llama: blue infinity/meta logo
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#0668e1';
        ctx.fill();
        ctx.stroke();
        // Infinity shape
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = stroke_width + 2;
        ctx.beginPath();
        ctx.arc(centerX - size * 0.12, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.stroke();
        ctx.beginPath();
        ctx.arc(centerX + size * 0.12, centerY, size * 0.12, 0, Math.PI * 2);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'deepseek':
        // DeepSeek: blue with DS
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#4d6bfe';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.22}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('DS', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'qwen':
        // Qwen: purple with Q
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#6366f1';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.35}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('Q', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'mistral':
        // Mistral: orange/yellow gradient circle with M
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#f97316';
        ctx.fill();
        ctx.stroke();
        // Stripes pattern
        ctx.fillStyle = '#000000';
        for (let i = 0; i < 4; i++) {
          ctx.fillRect(x + width * 0.25 + i * width * 0.12, y + height * 0.3, width * 0.06, height * 0.4);
        }
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'xai':
        // xAI/Grok: white X on black
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#000000';
        ctx.fill();
        ctx.stroke();
        // X logo
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = stroke_width + 3;
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.2, centerY - size * 0.2);
        ctx.lineTo(centerX + size * 0.2, centerY + size * 0.2);
        ctx.moveTo(centerX + size * 0.2, centerY - size * 0.2);
        ctx.lineTo(centerX - size * 0.2, centerY + size * 0.2);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'kimi':
        // Kimi/Moonshot: dark blue with moon
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#1a1a2e';
        ctx.fill();
        ctx.stroke();
        // Moon crescent
        ctx.fillStyle = '#fbbf24';
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.22, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#1a1a2e';
        ctx.beginPath();
        ctx.arc(centerX + size * 0.1, centerY - size * 0.05, size * 0.18, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'zhipu':
        // Zhipu AI (Z AI): green circle with Z
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#10b981';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.35}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('Z', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'cohere':
        // Cohere: coral/pink circle with C
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#d946ef';
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = '#ffffff';
        ctx.font = `bold ${size * 0.35}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('C', centerX, centerY);
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'huggingface':
        // Hugging Face: yellow with emoji face
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#ffd21e';
        ctx.fill();
        ctx.stroke();
        // Simple smiley face
        ctx.fillStyle = '#1e1e2e';
        ctx.beginPath();
        ctx.arc(centerX - size * 0.12, centerY - size * 0.08, size * 0.05, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.12, centerY - size * 0.08, size * 0.05, 0, Math.PI * 2);
        ctx.fill();
        // Smile
        ctx.strokeStyle = '#1e1e2e';
        ctx.lineWidth = stroke_width + 1;
        ctx.beginPath();
        ctx.arc(centerX, centerY + size * 0.02, size * 0.15, 0.2, Math.PI - 0.2);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'ollama':
        // Ollama: white circle with llama head
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#ffffff';
        ctx.fill();
        ctx.stroke();
        // Simple llama shape
        ctx.fillStyle = '#1e1e2e';
        ctx.beginPath();
        ctx.ellipse(centerX, centerY + size * 0.05, size * 0.15, size * 0.2, 0, 0, Math.PI * 2);
        ctx.fill();
        // Ears
        ctx.beginPath();
        ctx.ellipse(centerX - size * 0.12, centerY - size * 0.18, size * 0.04, size * 0.1, -0.3, 0, Math.PI * 2);
        ctx.ellipse(centerX + size * 0.12, centerY - size * 0.18, size * 0.04, size * 0.1, 0.3, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      case 'llm_generic':
        // Generic LLM/AI: brain icon
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.38, 0, Math.PI * 2);
        ctx.fillStyle = '#8b5cf6';
        ctx.fill();
        ctx.stroke();
        // Brain pattern
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = stroke_width + 1;
        ctx.beginPath();
        ctx.arc(centerX - size * 0.08, centerY - size * 0.05, size * 0.12, 0, Math.PI * 2);
        ctx.arc(centerX + size * 0.08, centerY - size * 0.05, size * 0.12, 0, Math.PI * 2);
        ctx.arc(centerX, centerY + size * 0.1, size * 0.1, 0, Math.PI * 2);
        ctx.stroke();
        // Connection lines
        ctx.beginPath();
        ctx.moveTo(centerX - size * 0.08, centerY + size * 0.05);
        ctx.lineTo(centerX, centerY + size * 0.1);
        ctx.lineTo(centerX + size * 0.08, centerY + size * 0.05);
        ctx.stroke();
        ctx.strokeStyle = stroke_color || '#3b82f6';
        ctx.lineWidth = stroke_width;
        ctx.fillStyle = fill_color || 'rgba(59, 130, 246, 0.2)';
        break;

      default:
        // Default: simple circle with question mark
        ctx.beginPath();
        ctx.arc(centerX, centerY, size * 0.35, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = stroke_color || '#3b82f6';
        ctx.font = `${size * 0.4}px Inter`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('?', centerX, centerY);
        break;
    }
  };

  const drawSelection = (ctx: CanvasRenderingContext2D, element: WhiteboardElement) => {
    ctx.strokeStyle = '#3b82f6';
    ctx.lineWidth = 2;
    ctx.setLineDash([5, 5]);
    ctx.strokeRect(
      element.x - 5,
      element.y - 5,
      element.width + 10,
      element.height + 10
    );
    ctx.setLineDash([]);

    // Draw resize handles
    const handles = [
      { x: element.x - 5, y: element.y - 5 },
      { x: element.x + element.width + 5, y: element.y - 5 },
      { x: element.x - 5, y: element.y + element.height + 5 },
      { x: element.x + element.width + 5, y: element.y + element.height + 5 },
    ];

    handles.forEach(handle => {
      ctx.fillStyle = '#3b82f6';
      ctx.fillRect(handle.x - 4, handle.y - 4, 8, 8);
    });
  };

  const drawRemoteCursors = (ctx: CanvasRenderingContext2D) => {
    remoteUsers.forEach(user => {
      const x = user.cursor_x * zoom + panOffset.x;
      const y = user.cursor_y * zoom + panOffset.y;

      // Draw cursor
      ctx.fillStyle = user.color;
      ctx.beginPath();
      ctx.moveTo(x, y);
      ctx.lineTo(x + 12, y + 10);
      ctx.lineTo(x + 5, y + 10);
      ctx.lineTo(x + 5, y + 18);
      ctx.lineTo(x, y);
      ctx.fill();

      // Draw name label
      ctx.font = '12px Inter';
      ctx.fillStyle = user.color;
      ctx.fillRect(x + 15, y + 15, ctx.measureText(user.username).width + 10, 20);
      ctx.fillStyle = '#ffffff';
      ctx.fillText(user.username, x + 20, y + 29);
    });
  };

  // Mouse handlers
  const getCanvasCoords = (e: React.MouseEvent) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return { x: 0, y: 0 };

    return {
      x: (e.clientX - rect.left - panOffset.x) / zoom,
      y: (e.clientY - rect.top - panOffset.y) / zoom,
    };
  };

  // Check if clicking on a resize handle
  const getResizeHandle = (coords: { x: number; y: number }, element: WhiteboardElement): string | null => {
    const handleSize = 8 / zoom;
    const handles = {
      'nw': { x: element.x - handleSize/2, y: element.y - handleSize/2 },
      'ne': { x: element.x + element.width - handleSize/2, y: element.y - handleSize/2 },
      'sw': { x: element.x - handleSize/2, y: element.y + element.height - handleSize/2 },
      'se': { x: element.x + element.width - handleSize/2, y: element.y + element.height - handleSize/2 },
    };

    for (const [name, pos] of Object.entries(handles)) {
      if (coords.x >= pos.x && coords.x <= pos.x + handleSize &&
          coords.y >= pos.y && coords.y <= pos.y + handleSize) {
        return name;
      }
    }
    return null;
  };

  const handleMouseDown = async (e: React.MouseEvent) => {
    const coords = getCanvasCoords(e);
    
    // Use ref for synchronous tool check to prevent race conditions
    const currentTool = selectedToolRef.current;

    if (currentTool === 'pan' || e.button === 1) {
      setIsPanning(true);
      return;
    }

    if (currentTool === 'select') {
      // Check if clicking on resize handle of selected element
      if (selectedElement && !lockedElements.has(selectedElement.element_id)) {
        const handle = getResizeHandle(coords, selectedElement);
        if (handle) {
          setIsResizing(true);
          setResizeHandle(handle);
          setDragStart({ x: coords.x, y: coords.y });
          setElementStart({
            x: selectedElement.x,
            y: selectedElement.y,
            width: selectedElement.width,
            height: selectedElement.height,
          });
          return;
        }
      }

      // Check if clicking on an element
      const clickedElement = elements.slice().reverse().find(el => 
        coords.x >= el.x && coords.x <= el.x + el.width &&
        coords.y >= el.y && coords.y <= el.y + el.height
      );

      if (clickedElement) {
        // Handle checklist item click
        if (clickedElement.element_type === 'checklist' && clickedElement.checklist_items) {
          const relativeX = coords.x - clickedElement.x;
          const relativeY = coords.y - clickedElement.y;
          
          // Check if click is on a checkbox (within the checkbox area)
          if (relativeX >= 8 && relativeX <= 36) {
            clickedElement.checklist_items.forEach((item, i) => {
              const itemY = 45 + i * 28;
              if (relativeY >= itemY - 14 && relativeY <= itemY + 10) {
                toggleChecklistItem(clickedElement, item.id);
              }
            });
          }
        }
        
        // Shift+click for multi-select
        if (e.shiftKey) {
          setMultiSelection(prev => {
            if (prev.includes(clickedElement.element_id)) {
              return prev.filter(id => id !== clickedElement.element_id);
            } else {
              return [...prev, clickedElement.element_id];
            }
          });
          setSelectedElement(null);
        } else if (multiSelection.includes(clickedElement.element_id)) {
          // Clicked on an already multi-selected element - start dragging all selected
          setSelectedElement(null);
          setIsDragging(true);
          setDragStart({ x: coords.x, y: coords.y });
          // Store original positions of all selected elements
          const startPositions: Record<string, { x: number; y: number }> = {};
          multiSelection.forEach(id => {
            const el = elements.find(e => e.element_id === id);
            if (el) {
              startPositions[id] = { x: el.x, y: el.y };
            }
          });
          setMultiElementStartPositions(startPositions);
        } else {
          // Clear multi-selection if not shift-clicking
          if (multiSelection.length > 0) {
            setMultiSelection([]);
          }
          
          // If clicking on the same element that's already selected, start editing
          if (selectedElement && clickedElement.element_id === selectedElement.element_id) {
            if (!lockedElements.has(clickedElement.element_id)) {
              // Text or sticky - start inline editing
              if (clickedElement.element_type === 'text' || clickedElement.element_type === 'sticky') {
                // Store element position in ref to prevent flickering
                editingElementRef.current = {
                  x: clickedElement.x,
                  y: clickedElement.y,
                  width: clickedElement.width,
                  height: clickedElement.height,
                  fill_color: clickedElement.fill_color,
                  stroke_color: clickedElement.stroke_color,
                  font_size: clickedElement.font_size,
                  element_type: clickedElement.element_type,
                };
                setEditingTextId(clickedElement.element_id);
                setEditingText(clickedElement.content || '');
                setTimeout(() => textInputRef.current?.focus(), 0);
                return;
              }
              // Table - edit clicked cell
              else if (clickedElement.element_type === 'table') {
                const cell = getTableCellAtPosition(clickedElement, coords.x, coords.y);
                if (cell) {
                  startEditingTableCell(clickedElement, cell.row, cell.col);
                  return;
                }
              }
            }
          }
          
          setSelectedElement(clickedElement);
          setElementOpacity(clickedElement.opacity || 1);
          
          // Only allow dragging if not locked
          if (!lockedElements.has(clickedElement.element_id)) {
            setIsDragging(true);
            setDragStart({ x: coords.x, y: coords.y });
            setElementStart({
              x: clickedElement.x,
              y: clickedElement.y,
              width: clickedElement.width,
              height: clickedElement.height,
            });
          }
          sendWsMessage({ type: 'select', element_id: clickedElement.element_id });
        }
      } else {
        // Start marquee selection when clicking on empty space
        setSelectedElement(null);
        if (!e.shiftKey) {
          setMultiSelection([]);
        }
        setIsSelectionBox(true);
        setSelectionBoxStart({ x: coords.x, y: coords.y });
        setSelectionBoxEnd({ x: coords.x, y: coords.y });
        sendWsMessage({ type: 'select', element_id: null });
      }
      return;
    }

    // Don't start a new shape if we're already drawing (prevents race conditions)
    if (isDrawing || drawingElement) {
      return;
    }

    // Handle sticky note placement - click to place with fixed dimensions
    if (currentTool === 'sticky') {
      const content = prompt('Enter sticky note text:');
      if (!content) return;
      
      const stickyWidth = 200;
      const stickyHeight = 150;
      const newSticky: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'sticky',
        x: snapToGridCoord(coords.x - stickyWidth / 2),
        y: snapToGridCoord(coords.y - stickyHeight / 2),
        width: stickyWidth,
        height: stickyHeight,
        rotation: 0,
        fill_color: selectedStickyColor || '#fef08a',
        stroke_color: '#e5e7eb',
        stroke_width: 1,
        opacity: 1,
        content: content,
        font_size: fontSize,
        z_index: elements.length,
        sticky_size: 'medium',
      };

      setElements(prev => [...prev, newSticky]);
      sendWsMessage({ type: 'create', element: newSticky });
      
      try {
        await whiteboardClient.createElement(Number(whiteboardId), newSticky);
      } catch (error) {
        console.error('Failed to save sticky note:', error);
      }

      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newSticky]]);
      setHistoryIndex(prev => prev + 1);
      
      selectedToolRef.current = 'select';
      setSelectedTool('select');
      setSelectedElement(newSticky);
      setSnackbar({ open: true, message: 'Sticky note created', severity: 'success' });
      return;
    }

    if (['rectangle', 'ellipse', 'line', 'arrow', 'bidirectional_arrow', 'text', 'triangle', 'diamond', 'hexagon', 'star'].includes(currentTool)) {
      setIsDrawing(true);
      const newElement: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: currentTool as WhiteboardElement['element_type'],
        x: snapToGridCoord(coords.x),
        y: snapToGridCoord(coords.y),
        width: 0,
        height: 0,
        rotation: 0,
        fill_color: fillColor,
        stroke_color: strokeColor,
        stroke_width: strokeWidth,
        opacity: elementOpacity,
        font_size: fontSize,
        z_index: elements.length,
      };

      setDrawingElement(newElement);
      return;
    }

    // Handle timer placement
    if (currentTool === 'timer') {
      const duration = prompt('Enter timer duration in minutes (e.g., 5, 10, 15):', '5');
      if (!duration) return;
      
      const timerSize = 120;
      const newTimer: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'timer',
        x: snapToGridCoord(coords.x - timerSize / 2),
        y: snapToGridCoord(coords.y - timerSize / 2),
        width: timerSize,
        height: timerSize,
        rotation: 0,
        fill_color: '#1e293b',
        stroke_color: '#3b82f6',
        stroke_width: 4,
        opacity: 1,
        z_index: elements.length,
        timer_duration: parseInt(duration) * 60,
        timer_started_at: Date.now(),
      };

      setElements(prev => [...prev, newTimer]);
      sendWsMessage({ type: 'create', element: newTimer });
      
      try {
        await whiteboardClient.createElement(Number(whiteboardId), newTimer);
      } catch (error) {
        console.error('Failed to save timer:', error);
      }

      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newTimer]]);
      setHistoryIndex(prev => prev + 1);
      
      selectedToolRef.current = 'select';
      setSelectedTool('select');
      setSelectedElement(newTimer);
      setSnackbar({ open: true, message: `Timer started: ${duration} minutes`, severity: 'success' });
      return;
    }

    // Handle table placement
    if (currentTool === 'table') {
      const rowsInput = prompt('Enter number of rows:', '3');
      if (!rowsInput) return;
      const colsInput = prompt('Enter number of columns:', '3');
      if (!colsInput) return;
      
      const rows = parseInt(rowsInput) || 3;
      const cols = parseInt(colsInput) || 3;
      
      const newTable: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'table',
        x: snapToGridCoord(coords.x),
        y: snapToGridCoord(coords.y),
        width: cols * 100,
        height: rows * 40,
        rotation: 0,
        fill_color: '#1e293b',
        stroke_color: '#64748b',
        stroke_width: 1,
        opacity: 1,
        z_index: elements.length,
        table_rows: rows,
        table_cols: cols,
        table_data: Array(rows).fill(null).map(() => Array(cols).fill('')),
      };

      setElements(prev => [...prev, newTable]);
      sendWsMessage({ type: 'create', element: newTable });
      
      try {
        await whiteboardClient.createElement(Number(whiteboardId), newTable);
      } catch (error) {
        console.error('Failed to save table:', error);
      }

      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newTable]]);
      setHistoryIndex(prev => prev + 1);
      
      selectedToolRef.current = 'select';
      setSelectedTool('select');
      setSelectedElement(newTable);
      setSnackbar({ open: true, message: `Table ${rows}x${cols} created`, severity: 'success' });
      return;
    }

    // Handle code block placement
    if (currentTool === 'code') {
      const language = prompt('Enter programming language (e.g., javascript, python, typescript):', 'javascript');
      if (!language) return;
      
      const newCode: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'code',
        x: snapToGridCoord(coords.x),
        y: snapToGridCoord(coords.y),
        width: 400,
        height: 200,
        rotation: 0,
        fill_color: '#1e1e2e',
        stroke_color: '#4b5563',
        stroke_width: 1,
        opacity: 1,
        z_index: elements.length,
        code_language: language,
        content: '// Your code here\n',
      };

      setElements(prev => [...prev, newCode]);
      sendWsMessage({ type: 'create', element: newCode });
      
      try {
        await whiteboardClient.createElement(Number(whiteboardId), newCode);
      } catch (error) {
        console.error('Failed to save code block:', error);
      }

      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newCode]]);
      setHistoryIndex(prev => prev + 1);
      
      selectedToolRef.current = 'select';
      setSelectedTool('select');
      setSelectedElement(newCode);
      setSnackbar({ open: true, message: `Code block (${language}) created`, severity: 'success' });
      return;
    }

    // Handle checklist placement
    if (currentTool === 'checklist') {
      const title = prompt('Enter checklist title:', 'Tasks');
      if (!title) return;
      
      const newChecklist: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'checklist',
        x: snapToGridCoord(coords.x),
        y: snapToGridCoord(coords.y),
        width: 250,
        height: 200,
        rotation: 0,
        fill_color: '#ffffff',
        stroke_color: '#e5e7eb',
        stroke_width: 1,
        opacity: 1,
        z_index: elements.length,
        label: title,
        checklist_items: [
          { id: `item_${Date.now()}_1`, text: 'Task 1', checked: false },
          { id: `item_${Date.now()}_2`, text: 'Task 2', checked: false },
          { id: `item_${Date.now()}_3`, text: 'Task 3', checked: false },
        ],
      };

      setElements(prev => [...prev, newChecklist]);
      sendWsMessage({ type: 'create', element: newChecklist });
      
      try {
        await whiteboardClient.createElement(Number(whiteboardId), newChecklist);
      } catch (error) {
        console.error('Failed to save checklist:', error);
      }

      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newChecklist]]);
      setHistoryIndex(prev => prev + 1);
      
      selectedToolRef.current = 'select';
      setSelectedTool('select');
      setSelectedElement(newChecklist);
      setSnackbar({ open: true, message: 'Checklist created', severity: 'success' });
      return;
    }

    // Handle link placement
    if (currentTool === 'link') {
      setPendingLinkPosition({ x: snapToGridCoord(coords.x), y: snapToGridCoord(coords.y) });
      setLinkDialogOpen(true);
      return;
    }

    // Handle symbol placement
    if (currentTool === 'symbol' && selectedSymbol) {
      const symbolSize = 80; // Default symbol size
      const newSymbol: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'symbol',
        x: snapToGridCoord(coords.x - symbolSize / 2),
        y: snapToGridCoord(coords.y - symbolSize / 2),
        width: symbolSize,
        height: symbolSize,
        rotation: 0,
        fill_color: fillColor || 'rgba(59, 130, 246, 0.2)',
        stroke_color: strokeColor,
        stroke_width: strokeWidth,
        opacity: elementOpacity,
        z_index: elements.length,
        symbol_type: selectedSymbol,
      };

      // Prompt for label
      const label = prompt('Enter a label for this symbol (or leave empty):');
      if (label) {
        newSymbol.label = label;
      }

      // Add to elements
      setElements(prev => [...prev, newSymbol]);

      // Send to server
      sendWsMessage({ type: 'create', element: newSymbol });

      // Save to database
      try {
        await whiteboardClient.createElement(Number(whiteboardId), newSymbol);
      } catch (error) {
        console.error('Failed to save symbol:', error);
      }

      // Update history
      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newSymbol]]);
      setHistoryIndex(prev => prev + 1);

      // Switch to select mode and select the new symbol
      setSelectedTool('select');
      selectedToolRef.current = 'select'; // Update ref immediately
      setSelectedElement(newSymbol);
      
      setSnackbar({ 
        open: true, 
        message: `Added ${NETWORK_SYMBOLS.find(s => s.id === selectedSymbol)?.name || 'symbol'}`, 
        severity: 'success' 
      });
    }

    if (currentTool === 'freehand') {
      setIsDrawing(true);
      setFreehandPoints([coords]);
    }

    // Connector tool - click on elements to connect them
    if (currentTool === 'connector') {
      const clickedElement = elements.slice().reverse().find(el => 
        el.element_type !== 'connector' &&
        coords.x >= el.x && coords.x <= el.x + el.width &&
        coords.y >= el.y && coords.y <= el.y + el.height
      );

      if (clickedElement) {
        if (!connectorStart) {
          // First click - set start element
          setConnectorStart({ 
            elementId: clickedElement.element_id, 
            x: clickedElement.x + clickedElement.width / 2, 
            y: clickedElement.y + clickedElement.height / 2 
          });
          setSnackbar({ open: true, message: 'Click on another element to complete connection', severity: 'info' });
        } else if (connectorStart.elementId !== clickedElement.element_id) {
          // Second click - create connector
          const connectorStyle = prompt('Connector style (straight, curved, elbow):', 'straight') || 'straight';
          
          const newConnector: WhiteboardElement = {
            element_id: generateElementId(),
            element_type: 'connector',
            x: Math.min(connectorStart.x, clickedElement.x + clickedElement.width / 2),
            y: Math.min(connectorStart.y, clickedElement.y + clickedElement.height / 2),
            width: Math.abs(clickedElement.x + clickedElement.width / 2 - connectorStart.x),
            height: Math.abs(clickedElement.y + clickedElement.height / 2 - connectorStart.y),
            rotation: 0,
            fill_color: 'transparent',
            stroke_color: strokeColor,
            stroke_width: strokeWidth,
            opacity: 1,
            z_index: 0, // Connectors go behind elements
            start_element_id: connectorStart.elementId,
            end_element_id: clickedElement.element_id,
            connector_style: connectorStyle as 'straight' | 'curved' | 'elbow',
          };

          setElements(prev => [newConnector, ...prev]); // Add at beginning so it's behind
          sendWsMessage({ type: 'create', element: newConnector });
          
          try {
            await whiteboardClient.createElement(Number(whiteboardId), newConnector);
          } catch (error) {
            console.error('Failed to save connector:', error);
          }

          setHistory(prev => [...prev.slice(0, historyIndex + 1), [newConnector, ...elements]]);
          setHistoryIndex(prev => prev + 1);
          
          setConnectorStart(null);
          setSnackbar({ open: true, message: 'Connector created', severity: 'success' });
        }
      } else if (connectorStart) {
        // Clicked empty space - cancel connector
        setConnectorStart(null);
        setSnackbar({ open: true, message: 'Connector cancelled', severity: 'info' });
      }
      return;
    }

    // Eraser tool - click on elements to delete them
    if (currentTool === 'eraser') {
      const clickedElement = elements.slice().reverse().find(el => 
        coords.x >= el.x && coords.x <= el.x + el.width &&
        coords.y >= el.y && coords.y <= el.y + el.height
      );

      if (clickedElement && !lockedElements.has(clickedElement.element_id)) {
        // Delete the clicked element
        const remainingElements = elements.filter(el => el.element_id !== clickedElement.element_id);
        setElements(remainingElements);
        sendWsMessage({ type: 'delete', element_id: clickedElement.element_id });

        try {
          await whiteboardClient.deleteElement(Number(whiteboardId), clickedElement.element_id);
          setSnackbar({ open: true, message: 'Element deleted', severity: 'info' });
        } catch (error) {
          console.error('Failed to delete element:', error);
        }

        // Update history with correct remaining elements
        setHistory(prev => [...prev.slice(0, historyIndex + 1), remainingElements]);
        setHistoryIndex(prev => prev + 1);
      }
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    const coords = getCanvasCoords(e);

    // Send cursor position to other users
    sendWsMessage({ type: 'cursor_move', x: coords.x, y: coords.y });

    if (isPanning) {
      setPanOffset(prev => ({
        x: prev.x + e.movementX,
        y: prev.y + e.movementY,
      }));
      return;
    }

    // Handle dragging element
    if (isDragging && selectedElement) {
      const dx = coords.x - dragStart.x;
      const dy = coords.y - dragStart.y;
      const newX = snapToGridCoord(elementStart.x + dx);
      const newY = snapToGridCoord(elementStart.y + dy);
      
      setElements(prev => prev.map(el =>
        el.element_id === selectedElement.element_id
          ? { ...el, x: newX, y: newY }
          : el
      ));
      setSelectedElement(prev => prev ? { ...prev, x: newX, y: newY } : null);
      return;
    }

    // Handle resizing element
    if (isResizing && selectedElement && resizeHandle) {
      const dx = coords.x - dragStart.x;
      const dy = coords.y - dragStart.y;
      
      let newX = elementStart.x;
      let newY = elementStart.y;
      let newWidth = elementStart.width;
      let newHeight = elementStart.height;

      if (resizeHandle.includes('w')) {
        newX = elementStart.x + dx;
        newWidth = elementStart.width - dx;
      }
      if (resizeHandle.includes('e')) {
        newWidth = elementStart.width + dx;
      }
      if (resizeHandle.includes('n')) {
        newY = elementStart.y + dy;
        newHeight = elementStart.height - dy;
      }
      if (resizeHandle.includes('s')) {
        newHeight = elementStart.height + dy;
      }

      // Ensure minimum size
      if (newWidth < 10) { newWidth = 10; newX = elementStart.x + elementStart.width - 10; }
      if (newHeight < 10) { newHeight = 10; newY = elementStart.y + elementStart.height - 10; }

      // Apply snap to grid
      newX = snapToGridCoord(newX);
      newY = snapToGridCoord(newY);
      newWidth = snapToGridCoord(newWidth);
      newHeight = snapToGridCoord(newHeight);

      setElements(prev => prev.map(el =>
        el.element_id === selectedElement.element_id
          ? { ...el, x: newX, y: newY, width: newWidth, height: newHeight }
          : el
      ));
      setSelectedElement(prev => prev ? { ...prev, x: newX, y: newY, width: newWidth, height: newHeight } : null);
      return;
    }

    if (isDrawing && drawingElement) {
      setDrawingElement(prev => prev ? {
        ...prev,
        width: snapToGridCoord(coords.x - prev.x),
        height: snapToGridCoord(coords.y - prev.y),
      } : null);
    }

    if (isDrawing && selectedTool === 'freehand') {
      setFreehandPoints(prev => [...prev, coords]);
    }

    // Update marquee selection box
    if (isSelectionBox) {
      setSelectionBoxEnd({ x: coords.x, y: coords.y });
    }

    // Multi-element drag - use stored start positions to avoid drift
    if (isDragging && multiSelection.length > 0 && !selectedElement) {
      const dx = coords.x - dragStart.x;
      const dy = coords.y - dragStart.y;
      
      setElements(prev => prev.map(el => {
        if (multiSelection.includes(el.element_id) && !lockedElements.has(el.element_id)) {
          const startPos = multiElementStartPositions[el.element_id];
          if (startPos) {
            return {
              ...el,
              x: snapToGridCoord(startPos.x + dx),
              y: snapToGridCoord(startPos.y + dy),
            };
          }
        }
        return el;
      }));
    }

    // Update cursor based on hover
    if (selectedTool === 'select' && selectedElement) {
      const handle = getResizeHandle(coords, selectedElement);
      const canvas = canvasRef.current;
      if (canvas) {
        if (handle === 'nw' || handle === 'se') canvas.style.cursor = 'nwse-resize';
        else if (handle === 'ne' || handle === 'sw') canvas.style.cursor = 'nesw-resize';
        else if (coords.x >= selectedElement.x && coords.x <= selectedElement.x + selectedElement.width &&
                 coords.y >= selectedElement.y && coords.y <= selectedElement.y + selectedElement.height) {
          canvas.style.cursor = 'move';
        } else {
          canvas.style.cursor = 'default';
        }
      }
    }
  };

  const handleMouseUp = async () => {
    // Finalize marquee selection
    if (isSelectionBox) {
      const x1 = Math.min(selectionBoxStart.x, selectionBoxEnd.x);
      const y1 = Math.min(selectionBoxStart.y, selectionBoxEnd.y);
      const x2 = Math.max(selectionBoxStart.x, selectionBoxEnd.x);
      const y2 = Math.max(selectionBoxStart.y, selectionBoxEnd.y);
      
      // Find all elements within the selection box
      const selectedIds = elements
        .filter(el => {
          // Check if element overlaps with selection box
          const elX1 = el.x;
          const elY1 = el.y;
          const elX2 = el.x + el.width;
          const elY2 = el.y + el.height;
          
          return elX1 < x2 && elX2 > x1 && elY1 < y2 && elY2 > y1;
        })
        .map(el => el.element_id);
      
      if (selectedIds.length > 0) {
        setMultiSelection(selectedIds);
        setSnackbar({ open: true, message: `Selected ${selectedIds.length} element${selectedIds.length > 1 ? 's' : ''}`, severity: 'info' });
      }
      
      setIsSelectionBox(false);
      return;
    }

    // Save changes after multi-element drag
    if (isDragging && multiSelection.length > 0 && !selectedElement) {
      // Update all dragged elements on server
      for (const elementId of multiSelection) {
        const el = elements.find(e => e.element_id === elementId);
        if (el && !lockedElements.has(elementId)) {
          sendWsMessage({ type: 'update', element_id: elementId, updates: { x: el.x, y: el.y }});
          try {
            await whiteboardClient.updateElement(Number(whiteboardId), elementId, { x: el.x, y: el.y });
          } catch (error) {
            console.error('Failed to update element:', error);
          }
        }
      }
      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements]]);
      setHistoryIndex(prev => prev + 1);
      setIsDragging(false);
      return;
    }

    // Save changes after drag/resize
    if ((isDragging || isResizing) && selectedElement) {
      sendWsMessage({ type: 'update', element_id: selectedElement.element_id, updates: {
        x: selectedElement.x,
        y: selectedElement.y,
        width: selectedElement.width,
        height: selectedElement.height,
      }});

      try {
        await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, {
          x: selectedElement.x,
          y: selectedElement.y,
          width: selectedElement.width,
          height: selectedElement.height,
        });
      } catch (error) {
        console.error('Failed to update element:', error);
      }

      // Update history
      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements]]);
      setHistoryIndex(prev => prev + 1);
    }

    setIsPanning(false);
    setIsDragging(false);
    setIsResizing(false);
    setResizeHandle(null);

    if (isDrawing && drawingElement) {
      // IMMEDIATELY switch to select mode and clear drawing state to prevent race conditions
      // This must happen BEFORE any async operations
      selectedToolRef.current = 'select';
      setSelectedTool('select');
      setIsDrawing(false);
      
      // Finalize element
      const finalElement = { ...drawingElement };
      
      // Clear drawing element immediately
      setDrawingElement(null);

      // Handle text element - create with placeholder and start inline editing
      if (finalElement.element_type === 'text') {
        finalElement.content = '';
        finalElement.width = Math.max(finalElement.width, 150);
        finalElement.height = Math.max(finalElement.height, 30);
        
        // Add to elements first
        setElements(prev => [...prev, finalElement]);
        setSelectedElement(finalElement);
        sendWsMessage({ type: 'create', element: finalElement });
        
        // Save to database
        try {
          await whiteboardClient.createElement(Number(whiteboardId), {
            element_id: finalElement.element_id,
            element_type: finalElement.element_type,
            x: finalElement.x,
            y: finalElement.y,
            width: finalElement.width,
            height: finalElement.height,
            rotation: finalElement.rotation,
            fill_color: finalElement.fill_color,
            stroke_color: finalElement.stroke_color,
            stroke_width: finalElement.stroke_width,
            opacity: finalElement.opacity,
            content: finalElement.content,
            font_size: finalElement.font_size,
            z_index: finalElement.z_index,
          });
        } catch (error) {
          console.error('Failed to save element:', error);
        }
        
        // Update history
        setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, finalElement]]);
        setHistoryIndex(prev => prev + 1);
        
        // Start inline editing immediately
        setTimeout(() => {
          // Store element position in ref to prevent flickering
          editingElementRef.current = {
            x: finalElement.x,
            y: finalElement.y,
            width: finalElement.width,
            height: finalElement.height,
            fill_color: finalElement.fill_color,
            stroke_color: finalElement.stroke_color,
            font_size: finalElement.font_size,
            element_type: finalElement.element_type,
          };
          setEditingTextId(finalElement.element_id);
          setEditingText('');
          textInputRef.current?.focus();
        }, 50);
        
        return;
      }
      
      // Handle sticky note - Sticky notes are click-to-place, so this shouldn't happen
      // But keep backward compatibility
      if (finalElement.element_type === 'sticky') {
        finalElement.content = finalElement.content || '';
      }

      // Add to elements and select the new element
      setElements(prev => [...prev, finalElement]);
      setSelectedElement(finalElement);

      // Send to server
      sendWsMessage({ type: 'create', element: finalElement });

      // Save to database (async - but we've already updated all state)
      try {
        await whiteboardClient.createElement(Number(whiteboardId), {
          element_id: finalElement.element_id,
          element_type: finalElement.element_type,
          x: finalElement.x,
          y: finalElement.y,
          width: finalElement.width,
          height: finalElement.height,
          rotation: finalElement.rotation,
          fill_color: finalElement.fill_color,
          stroke_color: finalElement.stroke_color,
          stroke_width: finalElement.stroke_width,
          opacity: finalElement.opacity,
          content: finalElement.content,
          font_size: finalElement.font_size,
          z_index: finalElement.z_index,
        });
      } catch (error) {
        console.error('Failed to save element:', error);
      }

      // Update history
      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, finalElement]]);
      setHistoryIndex(prev => prev + 1);
      
      return;
    }

    if (isDrawing && selectedTool === 'freehand' && freehandPoints.length > 1) {
      const bounds = freehandPoints.reduce(
        (acc, p) => ({
          minX: Math.min(acc.minX, p.x),
          minY: Math.min(acc.minY, p.y),
          maxX: Math.max(acc.maxX, p.x),
          maxY: Math.max(acc.maxY, p.y),
        }),
        { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity }
      );

      const finalElement: WhiteboardElement = {
        element_id: generateElementId(),
        element_type: 'freehand',
        x: bounds.minX,
        y: bounds.minY,
        width: bounds.maxX - bounds.minX,
        height: bounds.maxY - bounds.minY,
        rotation: 0,
        fill_color: null,
        stroke_color: strokeColor,
        stroke_width: strokeWidth,
        opacity: 1,
        points: freehandPoints,
        z_index: elements.length,
      };

      setElements(prev => [...prev, finalElement]);
      sendWsMessage({ type: 'create', element: finalElement });
      
      // Save freehand to database
      try {
        await whiteboardClient.createElement(Number(whiteboardId), finalElement);
      } catch (error) {
        console.error('Failed to save freehand element:', error);
      }
      
      // Update history
      setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, finalElement]]);
      setHistoryIndex(prev => prev + 1);
      
      setFreehandPoints([]);
      
      // Switch to select mode and select the new element
      setSelectedTool('select');
      selectedToolRef.current = 'select'; // Update ref immediately
      setSelectedElement(finalElement);
    }

    setIsDrawing(false);
    setDrawingElement(null);
  };

  // Handle wheel for zoom
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(prev => Math.min(Math.max(prev * delta, 0.1), 5));
  };

  // Delete selected element
  const deleteSelected = async () => {
    if (!selectedElement) return;

    setElements(prev => prev.filter(el => el.element_id !== selectedElement.element_id));
    sendWsMessage({ type: 'delete', element_id: selectedElement.element_id });

    try {
      await whiteboardClient.deleteElement(Number(whiteboardId), selectedElement.element_id);
    } catch (error) {
      console.error('Failed to delete element:', error);
    }

    setSelectedElement(null);
  };

  // Undo/Redo
  const undo = () => {
    if (historyIndex > 0) {
      setHistoryIndex(prev => prev - 1);
      setElements(history[historyIndex - 1]);
    }
  };

  const redo = () => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(prev => prev + 1);
      setElements(history[historyIndex + 1]);
    }
  };

  // Right-click context menu handler
  const handleContextMenu = (e: React.MouseEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left - panOffset.x) / zoom;
    const y = (e.clientY - rect.top - panOffset.y) / zoom;

    // Find element at this position (exclude locked elements)
    const clickedElement = [...elements].reverse().find(el => {
      if (lockedElements.has(el.element_id)) return false;
      return x >= el.x && x <= el.x + (el.width || 0) && y >= el.y && y <= el.y + (el.height || 0);
    });

    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      element: clickedElement || null,
    });

    if (clickedElement) {
      setSelectedElement(clickedElement);
      setSelectedTool('select');
    }
  };

  const handleContextMenuClose = () => {
    setContextMenu(null);
  };

  const handleContextMenuDelete = async () => {
    if (contextMenu?.element) {
      const elementToDelete = contextMenu.element;
      setElements(prev => prev.filter(el => el.element_id !== elementToDelete.element_id));
      sendWsMessage({ type: 'delete', element_id: elementToDelete.element_id });

      try {
        await whiteboardClient.deleteElement(Number(whiteboardId), elementToDelete.element_id);
      } catch (error) {
        console.error('Failed to delete element:', error);
      }

      setSelectedElement(null);
      setSnackbar({ open: true, message: 'Element deleted', severity: 'success' });
    }
    setContextMenu(null);
  };

  const handleContextMenuDuplicate = () => {
    if (contextMenu?.element) {
      const original = contextMenu.element;
      const duplicated: WhiteboardElement = {
        ...original,
        element_id: generateElementId(),
        x: original.x + 20,
        y: original.y + 20,
        z_index: elements.length,
      };
      setElements(prev => [...prev, duplicated]);
      sendWsMessage({ type: 'create', element: duplicated });
      
      // Save to database
      whiteboardClient.createElement(Number(whiteboardId), duplicated).catch(console.error);
      
      setSelectedElement(duplicated);
      setSnackbar({ open: true, message: 'Element duplicated', severity: 'success' });
    }
    setContextMenu(null);
  };

  // Vote on an element (dot voting)
  const handleAddVote = async (color: string) => {
    if (contextMenu?.element) {
      const element = contextMenu.element;
      const currentUser = user?.id || 0;
      
      // Count existing votes by this user
      const userVotes = (element.votes || []).filter(v => v.user_id === currentUser);
      if (userVotes.length >= MAX_VOTES_PER_USER) {
        setSnackbar({ open: true, message: `Maximum ${MAX_VOTES_PER_USER} votes per element`, severity: 'info' });
        setContextMenu(null);
        return;
      }
      
      const newVote: Vote = { user_id: currentUser, color };
      const updatedElement = {
        ...element,
        votes: [...(element.votes || []), newVote],
      };
      
      setElements(prev => prev.map(el => 
        el.element_id === element.element_id ? updatedElement : el
      ));
      sendWsMessage({ type: 'update', element: updatedElement });
      
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
      } catch (error) {
        console.error('Failed to save vote:', error);
      }
      
      setSnackbar({ open: true, message: 'Vote added!', severity: 'success' });
    }
    setContextMenu(null);
  };

  // Remove vote from element
  const handleRemoveVote = async () => {
    if (contextMenu?.element) {
      const element = contextMenu.element;
      const currentUser = user?.id || 0;
      
      const votes = element.votes || [];
      const userVoteIndex = votes.findIndex(v => v.user_id === currentUser);
      
      if (userVoteIndex === -1) {
        setSnackbar({ open: true, message: 'No votes to remove', severity: 'info' });
        setContextMenu(null);
        return;
      }
      
      const newVotes = [...votes];
      newVotes.splice(userVoteIndex, 1);
      
      const updatedElement = {
        ...element,
        votes: newVotes,
      };
      
      setElements(prev => prev.map(el => 
        el.element_id === element.element_id ? updatedElement : el
      ));
      sendWsMessage({ type: 'update', element: updatedElement });
      
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
      } catch (error) {
        console.error('Failed to remove vote:', error);
      }
      
      setSnackbar({ open: true, message: 'Vote removed', severity: 'info' });
    }
    setContextMenu(null);
  };

  // Set element status
  const handleSetStatus = async (status: ElementStatus) => {
    if (contextMenu?.element) {
      const element = contextMenu.element;
      
      const updatedElement = {
        ...element,
        status,
      };
      
      setElements(prev => prev.map(el => 
        el.element_id === element.element_id ? updatedElement : el
      ));
      sendWsMessage({ type: 'update', element: updatedElement });
      
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
      } catch (error) {
        console.error('Failed to save status:', error);
      }
      
      const statusLabels: Record<ElementStatus, string> = {
        'none': 'Status cleared',
        'on_track': 'Marked as On Track',
        'at_risk': 'Marked as At Risk',
        'blocked': 'Marked as Blocked',
        'done': 'Marked as Done',
      };
      setSnackbar({ open: true, message: statusLabels[status], severity: 'success' });
    }
    setContextMenu(null);
  };

  // Set element priority
  const handleSetPriority = async (priority: ElementPriority) => {
    if (contextMenu?.element) {
      const element = contextMenu.element;
      
      const updatedElement = {
        ...element,
        priority,
      };
      
      setElements(prev => prev.map(el => 
        el.element_id === element.element_id ? updatedElement : el
      ));
      sendWsMessage({ type: 'update', element: updatedElement });
      
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
      } catch (error) {
        console.error('Failed to save priority:', error);
      }
      
      const priorityLabels: Record<ElementPriority, string> = {
        'none': 'Priority cleared',
        'p1': 'Set to P1 (High Priority)',
        'p2': 'Set to P2 (Medium Priority)',
        'p3': 'Set to P3 (Low Priority)',
      };
      setSnackbar({ open: true, message: priorityLabels[priority], severity: 'success' });
    }
    setContextMenu(null);
  };

  // Search elements by text content
  const handleSearch = (query: string) => {
    setSearchQuery(query);
    if (!query.trim()) {
      setSearchResults([]);
      return;
    }
    const lowerQuery = query.toLowerCase();
    const results = elements.filter(el => {
      const content = el.content?.toLowerCase() || '';
      const label = el.label?.toLowerCase() || '';
      const checklistText = el.checklist_items?.map(i => i.text).join(' ').toLowerCase() || '';
      return content.includes(lowerQuery) || label.includes(lowerQuery) || checklistText.includes(lowerQuery);
    });
    setSearchResults(results);
  };

  // Navigate to element from search
  const navigateToElement = (element: WhiteboardElement) => {
    // Center the canvas on the element
    const centerX = element.x + element.width / 2;
    const centerY = element.y + element.height / 2;
    setPanOffset({
      x: containerSize.width / 2 - centerX * zoom,
      y: containerSize.height / 2 - centerY * zoom,
    });
    setSelectedElement(element);
    setSearchOpen(false);
    setSearchQuery('');
    setSearchResults([]);
  };

  // AI Summarize all sticky notes
  const handleAiSummarize = async () => {
    setAiLoading(true);
    try {
      const stickies = elements.filter(el => el.element_type === 'sticky' && el.content);
      if (stickies.length === 0) {
        setAiResult('No sticky notes with content found on the whiteboard.');
        setAiLoading(false);
        return;
      }
      
      const stickyContents = stickies.map((s, i) => `${i + 1}. ${s.content}`).join('\n');
      const prompt = `Please summarize the following brainstorming ideas from sticky notes into key themes and actionable insights:\n\n${stickyContents}\n\nProvide a concise summary with bullet points.`;
      
      const response = await aiClient.chat([{ role: 'user', content: prompt }]);
      setAiResult(response.message || 'Unable to generate summary.');
    } catch (error) {
      console.error('AI summarize error:', error);
      setAiResult('Failed to generate summary. Please try again.');
    }
    setAiLoading(false);
  };

  // AI Auto-categorize sticky notes
  const handleAiCategorize = async () => {
    setAiLoading(true);
    try {
      const stickies = elements.filter(el => el.element_type === 'sticky' && el.content);
      if (stickies.length === 0) {
        setAiResult('No sticky notes with content found on the whiteboard.');
        setAiLoading(false);
        return;
      }
      
      const stickyContents = stickies.map((s, i) => `ID:${s.element_id} - "${s.content}"`).join('\n');
      const prompt = `Analyze these brainstorming ideas and assign each one to a category. Return a JSON array with format: [{"id": "element_id", "category": "CategoryName"}]. Categories should be concise (1-2 words). Ideas:\n\n${stickyContents}\n\nRespond ONLY with the JSON array, no explanation.`;
      
      const response = await aiClient.chat([{ role: 'user', content: prompt }]);
      
      try {
        const categories = JSON.parse(response.message || '[]');
        const updatedElements = elements.map(el => {
          const cat = categories.find((c: { id: string; category: string }) => c.id === el.element_id);
          if (cat) {
            return { ...el, ai_category: cat.category };
          }
          return el;
        });
        setElements(updatedElements);
        
        // Save updates
        for (const cat of categories) {
          const el = elements.find(e => e.element_id === cat.id);
          if (el) {
            try {
              await whiteboardClient.updateElement(Number(whiteboardId), cat.id, { ai_category: cat.category });
            } catch (e) { console.error(e); }
          }
        }
        
        setAiResult(`Successfully categorized ${categories.length} sticky notes!`);
      } catch (parseError) {
        setAiResult('AI response: ' + response.message);
      }
    } catch (error) {
      console.error('AI categorize error:', error);
      setAiResult('Failed to categorize. Please try again.');
    }
    setAiLoading(false);
  };

  // AI Generate ideas as sticky notes
  const handleAiGenerate = async () => {
    if (!aiPrompt.trim()) {
      setAiResult('Please enter a topic or prompt for idea generation.');
      return;
    }
    
    setAiLoading(true);
    try {
      const prompt = `Generate 6 creative brainstorming ideas for: "${aiPrompt}". Return a JSON array of strings, each being a concise idea (max 50 chars). Format: ["idea1", "idea2", ...]. Respond ONLY with the JSON array.`;
      
      const response = await aiClient.chat([{ role: 'user', content: prompt }]);
      
      try {
        const ideas = JSON.parse(response.message || '[]');
        const colors = ['#fef08a', '#fda4af', '#93c5fd', '#86efac', '#fdba74', '#c4b5fd'];
        
        // Create sticky notes in a grid
        const startX = panOffset.x > 0 ? 100 : -panOffset.x / zoom + 100;
        const startY = panOffset.y > 0 ? 100 : -panOffset.y / zoom + 100;
        
        const newStickies: WhiteboardElement[] = ideas.map((idea: string, i: number) => ({
          element_id: generateElementId(),
          element_type: 'sticky' as const,
          x: startX + (i % 3) * 220,
          y: startY + Math.floor(i / 3) * 170,
          width: 200,
          height: 150,
          rotation: 0,
          fill_color: colors[i % colors.length],
          stroke_color: '#000000',
          stroke_width: 0,
          opacity: 1,
          z_index: elements.length + i,
          content: idea,
        }));
        
        setElements(prev => [...prev, ...newStickies]);
        
        // Save to database
        for (const sticky of newStickies) {
          sendWsMessage({ type: 'create', element: sticky });
          try {
            await whiteboardClient.createElement(Number(whiteboardId), sticky);
          } catch (e) { console.error(e); }
        }
        
        setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, ...newStickies]]);
        setHistoryIndex(prev => prev + 1);
        
        setAiResult(`Generated ${ideas.length} ideas as sticky notes!`);
        setAiPrompt('');
      } catch (parseError) {
        setAiResult('AI response: ' + response.message);
      }
    } catch (error) {
      console.error('AI generate error:', error);
      setAiResult('Failed to generate ideas. Please try again.');
    }
    setAiLoading(false);
  };

  // Toggle checklist item
  const toggleChecklistItem = async (element: WhiteboardElement, itemId: string) => {
    if (!element.checklist_items) return;
    
    const updatedItems = element.checklist_items.map(item =>
      item.id === itemId ? { ...item, checked: !item.checked } : item
    );
    
    const updatedElement = { ...element, checklist_items: updatedItems };
    
    setElements(prev => prev.map(el =>
      el.element_id === element.element_id ? updatedElement : el
    ));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to update checklist:', error);
    }
  };

  // Add new checklist item
  const addChecklistItem = async (element: WhiteboardElement) => {
    const text = prompt('Enter new task:');
    if (!text) return;
    
    const newItem = { id: `item_${Date.now()}`, text, checked: false };
    const updatedItems = [...(element.checklist_items || []), newItem];
    
    const updatedElement = { ...element, checklist_items: updatedItems };
    
    setElements(prev => prev.map(el =>
      el.element_id === element.element_id ? updatedElement : el
    ));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to add checklist item:', error);
    }
  };

  // Apply gradient to selected element
  const applyGradient = async (gradient: { start: string; end: string; direction: 'horizontal' | 'vertical' | 'diagonal' }) => {
    if (!selectedElement) return;
    
    const updatedElement = { ...selectedElement, gradient, fill_color: null };
    
    setElements(prev => prev.map(el =>
      el.element_id === selectedElement.element_id ? updatedElement : el
    ));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to apply gradient:', error);
    }
    
    setGradientDialogOpen(false);
    setSnackbar({ open: true, message: 'Gradient applied', severity: 'success' });
  };

  // Apply font to selected element
  const applyFont = async (font: string) => {
    if (!selectedElement) return;
    
    const updatedElement = { ...selectedElement, font_family: font };
    
    setElements(prev => prev.map(el =>
      el.element_id === selectedElement.element_id ? updatedElement : el
    ));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to apply font:', error);
    }
    
    setFontMenuAnchor(null);
    setSnackbar({ open: true, message: `Font changed to ${font.split(',')[0]}`, severity: 'success' });
  };

  // Toggle text formatting
  const toggleTextFormat = async (format: 'bold' | 'italic' | 'underline') => {
    if (!selectedElement) return;
    
    const updates: Partial<WhiteboardElement> = {};
    if (format === 'bold') updates.text_bold = !selectedElement.text_bold;
    if (format === 'italic') updates.text_italic = !selectedElement.text_italic;
    if (format === 'underline') updates.text_underline = !selectedElement.text_underline;
    
    const updatedElement = { ...selectedElement, ...updates };
    
    setElements(prev => prev.map(el =>
      el.element_id === selectedElement.element_id ? updatedElement : el
    ));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, updates);
    } catch (error) {
      console.error('Failed to toggle format:', error);
    }
  };

  // === Link Element Handlers ===
  const handleCreateLink = async () => {
    if (!pendingLinkPosition || !linkUrl) return;
    
    const newLink: WhiteboardElement = {
      element_id: generateElementId(),
      element_type: 'link',
      x: snapToGridValue(pendingLinkPosition.x),
      y: snapToGridValue(pendingLinkPosition.y),
      width: 280,
      height: 60,
      rotation: 0,
      fill_color: '#ffffff',
      stroke_color: '#e5e7eb',
      stroke_width: 1,
      opacity: 1,
      z_index: elements.length,
      link_url: linkUrl,
      link_title: linkTitle || linkUrl,
    };
    
    setElements(prev => [...prev, newLink]);
    sendWsMessage({ type: 'create', element: newLink });
    
    try {
      await whiteboardClient.createElement(Number(whiteboardId), newLink);
    } catch (error) {
      console.error('Failed to save link:', error);
    }
    
    setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, newLink]]);
    setHistoryIndex(prev => prev + 1);
    
    setLinkDialogOpen(false);
    setLinkUrl('');
    setLinkTitle('');
    setPendingLinkPosition(null);
    setSnackbar({ open: true, message: 'Link added', severity: 'success' });
  };

  const openLinkInNewTab = (element: WhiteboardElement) => {
    if (element.link_url) {
      window.open(element.link_url, '_blank', 'noopener,noreferrer');
    }
  };

  // === Comment Handlers ===
  const addComment = async () => {
    if (!commentingElement || !newCommentText.trim()) return;
    
    // Parse @mentions from text
    const mentionRegex = /@(\w+)/g;
    const mentions: number[] = [];
    let match: RegExpExecArray | null;
    while ((match = mentionRegex.exec(newCommentText)) !== null) {
      const mentioned = collaborators.find(c => c.username.toLowerCase() === match![1].toLowerCase());
      if (mentioned) mentions.push(mentioned.user_id);
    }
    
    const newComment: ElementComment = {
      id: `cmt_${Date.now()}`,
      user_id: user?.id || 0,
      username: user?.username || 'Unknown',
      text: newCommentText,
      created_at: new Date().toISOString(),
      mentions,
    };
    
    const updatedComments = [...(commentingElement.comments || []), newComment];
    const updatedElement = { ...commentingElement, comments: updatedComments };
    
    setElements(prev => prev.map(el =>
      el.element_id === commentingElement.element_id ? updatedElement : el
    ));
    setCommentingElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), commentingElement.element_id, { comments: updatedComments });
    } catch (error) {
      console.error('Failed to add comment:', error);
    }
    
    setNewCommentText('');
    setSnackbar({ open: true, message: 'Comment added', severity: 'success' });
  };

  const deleteComment = async (commentId: string) => {
    if (!commentingElement) return;
    
    const updatedComments = (commentingElement.comments || []).filter(c => c.id !== commentId);
    const updatedElement = { ...commentingElement, comments: updatedComments };
    
    setElements(prev => prev.map(el =>
      el.element_id === commentingElement.element_id ? updatedElement : el
    ));
    setCommentingElement(updatedElement);
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), commentingElement.element_id, { comments: updatedComments });
    } catch (error) {
      console.error('Failed to delete comment:', error);
    }
  };

  // === Element Grouping Handlers ===
  const groupSelectedElements = async () => {
    if (multiSelection.length < 2) {
      setSnackbar({ open: true, message: 'Select at least 2 elements to group', severity: 'info' });
      return;
    }
    
    const newGroupId = generateGroupId();
    
    const updatedElements = elements.map(el => {
      if (multiSelection.includes(el.element_id)) {
        return { ...el, group_id: newGroupId };
      }
      return el;
    });
    
    setElements(updatedElements);
    setElementGroups(prev => ({ ...prev, [newGroupId]: multiSelection }));
    
    // Save updates
    for (const elId of multiSelection) {
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), elId, { group_id: newGroupId });
      } catch (e) { console.error(e); }
    }
    
    setMultiSelection([]);
    setSnackbar({ open: true, message: `Grouped ${multiSelection.length} elements`, severity: 'success' });
  };

  const ungroupSelectedElements = async () => {
    if (!selectedElement?.group_id && multiSelection.length === 0) {
      setSnackbar({ open: true, message: 'Select grouped elements to ungroup', severity: 'info' });
      return;
    }
    
    const groupId = selectedElement?.group_id || 
      elements.find(el => multiSelection.includes(el.element_id) && el.group_id)?.group_id;
    
    if (!groupId) return;
    
    const updatedElements = elements.map(el => {
      if (el.group_id === groupId) {
        const { group_id, ...rest } = el;
        return rest as WhiteboardElement;
      }
      return el;
    });
    
    setElements(updatedElements);
    setElementGroups(prev => {
      const { [groupId]: _, ...rest } = prev;
      return rest;
    });
    
    // Save updates
    const groupedElements = elements.filter(el => el.group_id === groupId);
    for (const el of groupedElements) {
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), el.element_id, { group_id: undefined });
      } catch (e) { console.error(e); }
    }
    
    setSelectedElement(null);
    setSnackbar({ open: true, message: 'Elements ungrouped', severity: 'success' });
  };

  const selectGroup = (groupId: string) => {
    const groupElements = elements.filter(el => el.group_id === groupId).map(el => el.element_id);
    setMultiSelection(groupElements);
    setSelectedElement(null);
  };

  // === Sticky Note Sizing ===
  const changeStickySize = async (size: 'small' | 'medium' | 'large') => {
    if (!selectedElement || selectedElement.element_type !== 'sticky') return;
    
    const newDimensions = STICKY_SIZES[size];
    const updatedElement = { 
      ...selectedElement, 
      width: newDimensions.width, 
      height: newDimensions.height,
      sticky_size: size 
    };
    
    setElements(prev => prev.map(el =>
      el.element_id === selectedElement.element_id ? updatedElement : el
    ));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to resize sticky:', error);
    }
    
    setStickySizeMenuAnchor(null);
    setSnackbar({ open: true, message: `Resized to ${size}`, severity: 'success' });
  };

  // === Table Cell Editing ===
  const getTableCellAtPosition = (element: WhiteboardElement, x: number, y: number): { row: number; col: number } | null => {
    if (element.element_type !== 'table') return null;
    const rows = element.table_rows || 3;
    const cols = element.table_cols || 3;
    const cellWidth = element.width / cols;
    const cellHeight = element.height / rows;
    
    const localX = x - element.x;
    const localY = y - element.y;
    
    if (localX < 0 || localY < 0 || localX > element.width || localY > element.height) return null;
    
    const col = Math.floor(localX / cellWidth);
    const row = Math.floor(localY / cellHeight);
    
    if (row >= 0 && row < rows && col >= 0 && col < cols) {
      return { row, col };
    }
    return null;
  };

  const startEditingTableCell = (element: WhiteboardElement, row: number, col: number) => {
    const currentValue = element.table_data?.[row]?.[col] || '';
    setEditingTableCell({ elementId: element.element_id, row, col });
    setTableCellText(currentValue);
    setTimeout(() => tableCellInputRef.current?.focus(), 0);
  };

  const saveTableCellEdit = async () => {
    if (!editingTableCell) return;
    
    const element = elements.find(e => e.element_id === editingTableCell.elementId);
    if (!element || !element.table_data) return;
    
    const newTableData = element.table_data.map((row, rIdx) =>
      rIdx === editingTableCell.row
        ? row.map((cell, cIdx) => cIdx === editingTableCell.col ? tableCellText : cell)
        : row
    );
    
    const updatedElement = { ...element, table_data: newTableData };
    setElements(prev => prev.map(e => e.element_id === element.element_id ? updatedElement : e));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, { table_data: newTableData });
    } catch (error) {
      console.error('Failed to save table cell:', error);
    }
    
    setEditingTableCell(null);
    setTableCellText('');
  };

  const addTableRow = async (position: 'above' | 'below') => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'table') return;
    const element = contextMenu.element;
    
    // Get clicked cell position from context menu coordinates
    const cell = getTableCellAtPosition(element, 
      (contextMenu.x - panOffset.x) / zoom, 
      (contextMenu.y - panOffset.y) / zoom
    );
    const insertIndex = cell ? (position === 'above' ? cell.row : cell.row + 1) : (position === 'above' ? 0 : element.table_rows || 3);
    
    const cols = element.table_cols || 3;
    const newRow = Array(cols).fill('');
    const newTableData = [...(element.table_data || [])];
    newTableData.splice(insertIndex, 0, newRow);
    
    const newRows = (element.table_rows || 3) + 1;
    const cellHeight = element.height / (element.table_rows || 3);
    
    const updatedElement = { 
      ...element, 
      table_rows: newRows,
      table_data: newTableData,
      height: element.height + cellHeight
    };
    
    setElements(prev => prev.map(e => e.element_id === element.element_id ? updatedElement : e));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to add table row:', error);
    }
    
    setContextMenu(null);
    setSnackbar({ open: true, message: `Row added ${position}`, severity: 'success' });
  };

  const addTableColumn = async (position: 'left' | 'right') => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'table') return;
    const element = contextMenu.element;
    
    // Get clicked cell position
    const cell = getTableCellAtPosition(element,
      (contextMenu.x - panOffset.x) / zoom,
      (contextMenu.y - panOffset.y) / zoom
    );
    const insertIndex = cell ? (position === 'left' ? cell.col : cell.col + 1) : (position === 'left' ? 0 : element.table_cols || 3);
    
    const newTableData = (element.table_data || []).map(row => {
      const newRow = [...row];
      newRow.splice(insertIndex, 0, '');
      return newRow;
    });
    
    const newCols = (element.table_cols || 3) + 1;
    const cellWidth = element.width / (element.table_cols || 3);
    
    const updatedElement = { 
      ...element, 
      table_cols: newCols,
      table_data: newTableData,
      width: element.width + cellWidth
    };
    
    setElements(prev => prev.map(e => e.element_id === element.element_id ? updatedElement : e));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to add table column:', error);
    }
    
    setContextMenu(null);
    setSnackbar({ open: true, message: `Column added ${position}`, severity: 'success' });
  };

  const deleteTableRow = async () => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'table') return;
    const element = contextMenu.element;
    
    if ((element.table_rows || 3) <= 1) {
      setSnackbar({ open: true, message: 'Cannot delete the last row', severity: 'info' });
      return;
    }
    
    const cell = getTableCellAtPosition(element,
      (contextMenu.x - panOffset.x) / zoom,
      (contextMenu.y - panOffset.y) / zoom
    );
    const deleteIndex = cell?.row ?? 0;
    
    const newTableData = (element.table_data || []).filter((_, idx) => idx !== deleteIndex);
    const newRows = (element.table_rows || 3) - 1;
    const cellHeight = element.height / (element.table_rows || 3);
    
    const updatedElement = { 
      ...element, 
      table_rows: newRows,
      table_data: newTableData,
      height: element.height - cellHeight
    };
    
    setElements(prev => prev.map(e => e.element_id === element.element_id ? updatedElement : e));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to delete table row:', error);
    }
    
    setContextMenu(null);
    setSnackbar({ open: true, message: 'Row deleted', severity: 'success' });
  };

  const deleteTableColumn = async () => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'table') return;
    const element = contextMenu.element;
    
    if ((element.table_cols || 3) <= 1) {
      setSnackbar({ open: true, message: 'Cannot delete the last column', severity: 'info' });
      return;
    }
    
    const cell = getTableCellAtPosition(element,
      (contextMenu.x - panOffset.x) / zoom,
      (contextMenu.y - panOffset.y) / zoom
    );
    const deleteIndex = cell?.col ?? 0;
    
    const newTableData = (element.table_data || []).map(row => row.filter((_, idx) => idx !== deleteIndex));
    const newCols = (element.table_cols || 3) - 1;
    const cellWidth = element.width / (element.table_cols || 3);
    
    const updatedElement = { 
      ...element, 
      table_cols: newCols,
      table_data: newTableData,
      width: element.width - cellWidth
    };
    
    setElements(prev => prev.map(e => e.element_id === element.element_id ? updatedElement : e));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, updatedElement);
    } catch (error) {
      console.error('Failed to delete table column:', error);
    }
    
    setContextMenu(null);
    setSnackbar({ open: true, message: 'Column deleted', severity: 'success' });
  };

  // === Timer Controls ===
  const startTimer = async () => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'timer') return;
    const element = contextMenu.element;
    
    const updatedElement = {
      ...element,
      timer_started_at: element.timer_paused_at 
        ? Date.now() - (element.timer_paused_at - (element.timer_started_at || Date.now()))
        : Date.now(),
      timer_paused_at: undefined,
    };
    
    setElements(prev => prev.map(e => 
      e.element_id === element.element_id ? updatedElement : e
    ));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, {
        timer_started_at: updatedElement.timer_started_at,
        timer_paused_at: undefined,
      });
    } catch (error) {
      console.error('Failed to start timer:', error);
    }
    
    handleContextMenuClose();
    setSnackbar({ open: true, message: 'Timer started', severity: 'success' });
  };

  const pauseTimer = async () => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'timer') return;
    const element = contextMenu.element;
    
    if (!element.timer_started_at || element.timer_paused_at) return;
    
    const updatedElement = {
      ...element,
      timer_paused_at: Date.now(),
    };
    
    setElements(prev => prev.map(e => 
      e.element_id === element.element_id ? updatedElement : e
    ));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, {
        timer_paused_at: updatedElement.timer_paused_at,
      });
    } catch (error) {
      console.error('Failed to pause timer:', error);
    }
    
    handleContextMenuClose();
    setSnackbar({ open: true, message: 'Timer paused', severity: 'info' });
  };

  const resetTimer = async () => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'timer') return;
    const element = contextMenu.element;
    
    const updatedElement = {
      ...element,
      timer_started_at: undefined,
      timer_paused_at: undefined,
    };
    
    setElements(prev => prev.map(e => 
      e.element_id === element.element_id ? updatedElement : e
    ));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, {
        timer_started_at: undefined,
        timer_paused_at: undefined,
      });
    } catch (error) {
      console.error('Failed to reset timer:', error);
    }
    
    handleContextMenuClose();
    setSnackbar({ open: true, message: 'Timer reset', severity: 'info' });
  };

  const setTimerDuration = async () => {
    if (!contextMenu?.element || contextMenu.element.element_type !== 'timer') return;
    const element = contextMenu.element;
    
    const currentDuration = element.timer_duration ? Math.floor(element.timer_duration / 60) : 5;
    const newDuration = prompt('Enter timer duration in minutes:', currentDuration.toString());
    if (!newDuration) return;
    
    const durationSeconds = parseInt(newDuration) * 60;
    const updatedElement = {
      ...element,
      timer_duration: durationSeconds,
      timer_started_at: undefined,
      timer_paused_at: undefined,
    };
    
    setElements(prev => prev.map(e => 
      e.element_id === element.element_id ? updatedElement : e
    ));
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), element.element_id, {
        timer_duration: durationSeconds,
        timer_started_at: undefined,
        timer_paused_at: undefined,
      });
    } catch (error) {
      console.error('Failed to set timer duration:', error);
    }
    
    handleContextMenuClose();
    setSnackbar({ open: true, message: `Timer set to ${newDuration} minutes`, severity: 'success' });
  };

  // === Auto Layout with AI ===
  const handleAutoLayout = async () => {
    setAiLoading(true);
    try {
      const layoutableElements = elements.filter(el => 
        ['sticky', 'rectangle', 'text', 'checklist', 'code', 'link'].includes(el.element_type)
      );
      
      if (layoutableElements.length < 2) {
        setAiResult('Need at least 2 elements for auto-layout.');
        setAiLoading(false);
        return;
      }
      
      const elementDescriptions = layoutableElements.map(el => ({
        id: el.element_id,
        type: el.element_type,
        content: el.content || el.label || el.link_title || '',
        category: el.ai_category || '',
        width: el.width,
        height: el.height,
      }));
      
      const canvasWidth = whiteboard?.canvas_width || 1920;
      const canvasHeight = whiteboard?.canvas_height || 1080;
      
      const prompt = `Arrange these whiteboard elements in a logical, visually appealing layout. Canvas size: ${canvasWidth}x${canvasHeight}.
Elements: ${JSON.stringify(elementDescriptions)}

Return a JSON array with format: [{"id": "element_id", "x": number, "y": number}]
Group similar/related elements together. Leave margins of at least 50px from edges.
Space elements evenly with at least 30px gap. Organize by category if available.
Respond ONLY with the JSON array.`;
      
      const response = await aiClient.chat([{ role: 'user', content: prompt }]);
      
      try {
        const positions = JSON.parse(response.message || '[]');
        const updatedElements = elements.map(el => {
          const pos = positions.find((p: { id: string; x: number; y: number }) => p.id === el.element_id);
          if (pos) {
            return { ...el, x: snapToGridValue(pos.x), y: snapToGridValue(pos.y) };
          }
          return el;
        });
        
        setElements(updatedElements);
        
        // Save updates
        for (const pos of positions) {
          try {
            await whiteboardClient.updateElement(Number(whiteboardId), pos.id, { x: pos.x, y: pos.y });
          } catch (e) { console.error(e); }
        }
        
        setHistory(prev => [...prev.slice(0, historyIndex + 1), updatedElements]);
        setHistoryIndex(prev => prev + 1);
        
        setAiResult(`Auto-arranged ${positions.length} elements!`);
      } catch (parseError) {
        setAiResult('AI response: ' + response.message);
      }
    } catch (error) {
      console.error('Auto-layout error:', error);
      setAiResult('Failed to auto-layout. Please try again.');
    }
    setAiLoading(false);
  };

  // === @Mentions Handler ===
  const handleMentionInput = (text: string) => {
    const lastAtIndex = text.lastIndexOf('@');
    if (lastAtIndex !== -1) {
      const query = text.substring(lastAtIndex + 1).toLowerCase();
      setMentionQuery(query);
      if (query.length > 0) {
        // Filter collaborators matching the query
        const matches = collaborators.filter(c => 
          c.username.toLowerCase().includes(query)
        );
        if (matches.length > 0) {
          // Show mentions popup
        }
      }
    }
  };

  const insertMention = (username: string) => {
    const lastAtIndex = newCommentText.lastIndexOf('@');
    if (lastAtIndex !== -1) {
      const newText = newCommentText.substring(0, lastAtIndex) + '@' + username + ' ';
      setNewCommentText(newText);
    }
    setMentionsAnchor(null);
  };

  // Export canvas as PNG or JPG
  const exportCanvas = (format: 'png' | 'jpeg' = 'png') => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Create a temporary canvas for full-quality export
    const exportCanvas = document.createElement('canvas');
    exportCanvas.width = whiteboard?.canvas_width || 1920;
    exportCanvas.height = whiteboard?.canvas_height || 1080;
    const ctx = exportCanvas.getContext('2d');
    if (!ctx) return;

    // Draw background
    ctx.fillStyle = whiteboard?.background_color || '#1e1e2e';
    ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);

    // Draw grid if enabled
    if (showGrid) {
      drawGrid(ctx, exportCanvas.width, exportCanvas.height);
    }

    // Draw all elements
    elements.forEach(element => {
      drawElement(ctx, element);
    });

    // Download
    const link = document.createElement('a');
    const ext = format === 'jpeg' ? 'jpg' : 'png';
    link.download = `${whiteboard?.name || 'whiteboard'}_${new Date().toISOString().slice(0, 10)}.${ext}`;
    link.href = exportCanvas.toDataURL(`image/${format}`, format === 'jpeg' ? 0.92 : undefined);
    link.click();

    setExportDialogOpen(false);
    setSnackbar({ open: true, message: `Whiteboard exported as ${ext.toUpperCase()}!`, severity: 'success' });
  };

  // Apply template to whiteboard
  const applyTemplate = async (templateType: 'retrospective' | 'swot' | 'mindmap' | 'riskmatrix') => {
    const canvasWidth = whiteboard?.canvas_width || 1920;
    const canvasHeight = whiteboard?.canvas_height || 1080;
    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;
    
    const newElements: WhiteboardElement[] = [];
    let zIndex = elements.length;

    const createSticky = (x: number, y: number, width: number, height: number, content: string, color: string): WhiteboardElement => ({
      element_id: generateElementId(),
      element_type: 'sticky',
      x, y, width, height,
      rotation: 0,
      fill_color: color,
      stroke_color: '#00000020',
      stroke_width: 1,
      opacity: 1,
      content,
      font_size: 14,
      z_index: zIndex++,
    });

    const createRect = (x: number, y: number, width: number, height: number, fillColor: string, strokeColor: string, label?: string): WhiteboardElement => ({
      element_id: generateElementId(),
      element_type: 'rectangle',
      x, y, width, height,
      rotation: 0,
      fill_color: fillColor,
      stroke_color: strokeColor,
      stroke_width: 2,
      opacity: 1,
      label,
      z_index: zIndex++,
    });

    const createText = (x: number, y: number, content: string, fontSize: number = 24): WhiteboardElement => ({
      element_id: generateElementId(),
      element_type: 'text',
      x, y,
      width: content.length * fontSize * 0.6,
      height: fontSize + 10,
      rotation: 0,
      fill_color: '#ffffff',
      stroke_color: '#ffffff',
      stroke_width: 1,
      opacity: 1,
      content,
      font_size: fontSize,
      z_index: zIndex++,
    });

    const createEllipse = (x: number, y: number, width: number, height: number, fillColor: string, strokeColor: string, label?: string): WhiteboardElement => ({
      element_id: generateElementId(),
      element_type: 'ellipse',
      x, y, width, height,
      rotation: 0,
      fill_color: fillColor,
      stroke_color: strokeColor,
      stroke_width: 2,
      opacity: 1,
      label,
      z_index: zIndex++,
    });

    const createLine = (x1: number, y1: number, x2: number, y2: number, color: string): WhiteboardElement => ({
      element_id: generateElementId(),
      element_type: 'line',
      x: x1, y: y1,
      width: x2 - x1,
      height: y2 - y1,
      rotation: 0,
      fill_color: null,
      stroke_color: color,
      stroke_width: 2,
      opacity: 1,
      z_index: zIndex++,
    });

    switch (templateType) {
      case 'retrospective': {
        // Title
        newElements.push(createText(centerX - 200, 50, '🔄 Sprint Retrospective', 32));
        
        // Three columns
        const colWidth = 350;
        const colHeight = 500;
        const startY = 120;
        const gap = 40;
        const startX = centerX - (colWidth * 1.5 + gap);

        // What went well (green)
        newElements.push(createRect(startX, startY, colWidth, colHeight, '#16a34a20', '#16a34a'));
        newElements.push(createText(startX + 20, startY + 15, '✅ What Went Well', 20));
        newElements.push(createSticky(startX + 20, startY + 60, 150, 100, 'Add your thoughts...', '#bbf7d0'));
        newElements.push(createSticky(startX + 180, startY + 60, 150, 100, '', '#bbf7d0'));
        newElements.push(createSticky(startX + 20, startY + 170, 150, 100, '', '#bbf7d0'));

        // What didn't go well (red)
        const col2X = startX + colWidth + gap;
        newElements.push(createRect(col2X, startY, colWidth, colHeight, '#dc262620', '#dc2626'));
        newElements.push(createText(col2X + 20, startY + 15, '❌ What Didn\'t Go Well', 20));
        newElements.push(createSticky(col2X + 20, startY + 60, 150, 100, 'Add your thoughts...', '#fecaca'));
        newElements.push(createSticky(col2X + 180, startY + 60, 150, 100, '', '#fecaca'));
        newElements.push(createSticky(col2X + 20, startY + 170, 150, 100, '', '#fecaca'));

        // Action items (blue)
        const col3X = col2X + colWidth + gap;
        newElements.push(createRect(col3X, startY, colWidth, colHeight, '#2563eb20', '#2563eb'));
        newElements.push(createText(col3X + 20, startY + 15, '🎯 Action Items', 20));
        newElements.push(createSticky(col3X + 20, startY + 60, 150, 100, 'Add action items...', '#bfdbfe'));
        newElements.push(createSticky(col3X + 180, startY + 60, 150, 100, '', '#bfdbfe'));
        newElements.push(createSticky(col3X + 20, startY + 170, 150, 100, '', '#bfdbfe'));
        break;
      }

      case 'swot': {
        // Title
        newElements.push(createText(centerX - 150, 30, '📊 SWOT Analysis', 32));
        
        const quadSize = 380;
        const startX = centerX - quadSize;
        const startY = 100;

        // Strengths (green - top left)
        newElements.push(createRect(startX, startY, quadSize, quadSize, '#16a34a15', '#16a34a'));
        newElements.push(createText(startX + 20, startY + 15, '💪 STRENGTHS', 22));
        newElements.push(createSticky(startX + 20, startY + 60, 160, 90, 'Internal positive', '#bbf7d0'));
        newElements.push(createSticky(startX + 200, startY + 60, 160, 90, '', '#bbf7d0'));
        newElements.push(createSticky(startX + 20, startY + 160, 160, 90, '', '#bbf7d0'));

        // Weaknesses (red - top right)
        newElements.push(createRect(startX + quadSize, startY, quadSize, quadSize, '#dc262615', '#dc2626'));
        newElements.push(createText(startX + quadSize + 20, startY + 15, '⚠️ WEAKNESSES', 22));
        newElements.push(createSticky(startX + quadSize + 20, startY + 60, 160, 90, 'Internal negative', '#fecaca'));
        newElements.push(createSticky(startX + quadSize + 200, startY + 60, 160, 90, '', '#fecaca'));
        newElements.push(createSticky(startX + quadSize + 20, startY + 160, 160, 90, '', '#fecaca'));

        // Opportunities (blue - bottom left)
        newElements.push(createRect(startX, startY + quadSize, quadSize, quadSize, '#2563eb15', '#2563eb'));
        newElements.push(createText(startX + 20, startY + quadSize + 15, '🚀 OPPORTUNITIES', 22));
        newElements.push(createSticky(startX + 20, startY + quadSize + 60, 160, 90, 'External positive', '#bfdbfe'));
        newElements.push(createSticky(startX + 200, startY + quadSize + 60, 160, 90, '', '#bfdbfe'));
        newElements.push(createSticky(startX + 20, startY + quadSize + 160, 160, 90, '', '#bfdbfe'));

        // Threats (orange - bottom right)
        newElements.push(createRect(startX + quadSize, startY + quadSize, quadSize, quadSize, '#ea580c15', '#ea580c'));
        newElements.push(createText(startX + quadSize + 20, startY + quadSize + 15, '⚡ THREATS', 22));
        newElements.push(createSticky(startX + quadSize + 20, startY + quadSize + 60, 160, 90, 'External negative', '#fed7aa'));
        newElements.push(createSticky(startX + quadSize + 200, startY + quadSize + 60, 160, 90, '', '#fed7aa'));
        newElements.push(createSticky(startX + quadSize + 20, startY + quadSize + 160, 160, 90, '', '#fed7aa'));

        // Labels
        newElements.push(createText(startX - 120, startY + quadSize - 20, 'INTERNAL', 16));
        newElements.push(createText(startX - 120, startY + quadSize + 20, 'EXTERNAL', 16));
        newElements.push(createText(centerX - 50, startY - 30, 'POSITIVE', 16));
        newElements.push(createText(centerX + quadSize - 60, startY - 30, 'NEGATIVE', 16));
        break;
      }

      case 'mindmap': {
        // Central idea
        const centralX = centerX - 100;
        const centralY = centerY - 50;
        newElements.push(createEllipse(centralX, centralY, 200, 100, '#8b5cf6', '#7c3aed', 'Main Idea'));
        newElements.push(createText(centralX + 40, centralY + 35, '🧠 Main Idea', 20));

        // Branches
        const branchColors = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#ec4899', '#06b6d4'];
        const branchLabels = ['Branch 1', 'Branch 2', 'Branch 3', 'Branch 4', 'Branch 5', 'Branch 6'];
        const branchPositions = [
          { x: centerX - 400, y: centerY - 200, angle: -150 },
          { x: centerX + 200, y: centerY - 200, angle: -30 },
          { x: centerX + 300, y: centerY - 30, angle: 0 },
          { x: centerX + 200, y: centerY + 150, angle: 30 },
          { x: centerX - 400, y: centerY + 150, angle: 150 },
          { x: centerX - 500, y: centerY - 30, angle: 180 },
        ];

        branchPositions.forEach((pos, i) => {
          // Line from center to branch
          newElements.push(createLine(
            centralX + 100, centralY + 50,
            pos.x + 75, pos.y + 30,
            branchColors[i]
          ));
          
          // Branch ellipse
          newElements.push(createEllipse(pos.x, pos.y, 150, 60, branchColors[i] + '40', branchColors[i], branchLabels[i]));
          
          // Sub-branches (smaller)
          const subOffsets = [
            { dx: -80, dy: -50 },
            { dx: 100, dy: -40 },
            { dx: 80, dy: 50 },
          ];
          
          subOffsets.forEach((offset) => {
            const subX = pos.x + 75 + offset.dx;
            const subY = pos.y + 30 + offset.dy;
            newElements.push(createLine(pos.x + 75, pos.y + 30, subX + 40, subY + 15, branchColors[i] + '80'));
            newElements.push(createEllipse(subX, subY, 80, 30, branchColors[i] + '20', branchColors[i] + '60'));
          });
        });

        // Title
        newElements.push(createText(centerX - 100, 30, '🗺️ Mind Map', 32));
        break;
      }

      case 'riskmatrix': {
        // Title
        newElements.push(createText(centerX - 100, 30, '⚠️ Risk Matrix', 32));

        const gridSize = 160;
        const startX = centerX - (gridSize * 2.5);
        const startY = 120;

        // Y-axis label (Impact)
        newElements.push(createText(startX - 100, startY + gridSize * 2, 'IMPACT', 18));
        
        // X-axis label (Probability)
        newElements.push(createText(centerX - 60, startY + gridSize * 5 + 30, 'PROBABILITY', 18));

        // Impact labels (left side)
        const impactLabels = ['Critical', 'High', 'Medium', 'Low', 'Negligible'];
        impactLabels.forEach((label, i) => {
          newElements.push(createText(startX - 80, startY + gridSize * i + gridSize / 2 - 10, label, 12));
        });

        // Probability labels (bottom)
        const probLabels = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost Certain'];
        probLabels.forEach((label, i) => {
          newElements.push(createText(startX + gridSize * i + 20, startY + gridSize * 5 + 5, label, 11));
        });

        // Risk colors based on position (impact x probability)
        const getRiskColor = (row: number, col: number): string => {
          const score = (4 - row) + col; // 0-8 scale
          if (score <= 2) return '#22c55e30'; // Green - Low
          if (score <= 4) return '#eab30830'; // Yellow - Medium
          if (score <= 6) return '#f9731630'; // Orange - High
          return '#ef444430'; // Red - Critical
        };

        const getRiskBorder = (row: number, col: number): string => {
          const score = (4 - row) + col;
          if (score <= 2) return '#22c55e';
          if (score <= 4) return '#eab308';
          if (score <= 6) return '#f97316';
          return '#ef4444';
        };

        // Create grid cells
        for (let row = 0; row < 5; row++) {
          for (let col = 0; col < 5; col++) {
            newElements.push(createRect(
              startX + col * gridSize,
              startY + row * gridSize,
              gridSize,
              gridSize,
              getRiskColor(row, col),
              getRiskBorder(row, col)
            ));
          }
        }

        // Add sample risks
        newElements.push(createSticky(startX + 20, startY + gridSize * 3 + 20, 120, 80, 'Risk A\n(Low)', '#bbf7d0'));
        newElements.push(createSticky(startX + gridSize * 2 + 20, startY + gridSize * 2 + 20, 120, 80, 'Risk B\n(Medium)', '#fef08a'));
        newElements.push(createSticky(startX + gridSize * 3 + 20, startY + gridSize + 20, 120, 80, 'Risk C\n(High)', '#fed7aa'));
        newElements.push(createSticky(startX + gridSize * 4 + 20, startY + 20, 120, 80, 'Risk D\n(Critical)', '#fecaca'));

        // Legend
        newElements.push(createRect(startX + gridSize * 5 + 40, startY, 150, 200, '#1e293b', '#374151'));
        newElements.push(createText(startX + gridSize * 5 + 55, startY + 10, 'Legend', 16));
        newElements.push(createRect(startX + gridSize * 5 + 55, startY + 40, 20, 20, '#22c55e30', '#22c55e'));
        newElements.push(createText(startX + gridSize * 5 + 85, startY + 42, 'Low', 12));
        newElements.push(createRect(startX + gridSize * 5 + 55, startY + 70, 20, 20, '#eab30830', '#eab308'));
        newElements.push(createText(startX + gridSize * 5 + 85, startY + 72, 'Medium', 12));
        newElements.push(createRect(startX + gridSize * 5 + 55, startY + 100, 20, 20, '#f9731630', '#f97316'));
        newElements.push(createText(startX + gridSize * 5 + 85, startY + 102, 'High', 12));
        newElements.push(createRect(startX + gridSize * 5 + 55, startY + 130, 20, 20, '#ef444430', '#ef4444'));
        newElements.push(createText(startX + gridSize * 5 + 85, startY + 132, 'Critical', 12));
        break;
      }
    }

    // Add all elements
    setElements(prev => [...prev, ...newElements]);
    
    // Save to database and broadcast
    for (const el of newElements) {
      sendWsMessage({ type: 'create', element: el });
      try {
        await whiteboardClient.createElement(Number(whiteboardId), el);
      } catch (error) {
        console.error('Failed to save template element:', error);
      }
    }

    // Update history
    setHistory(prev => [...prev.slice(0, historyIndex + 1), [...elements, ...newElements]]);
    setHistoryIndex(prev => prev + 1);

    setTemplatesDialogOpen(false);
    setSnackbar({ open: true, message: `${templateType.charAt(0).toUpperCase() + templateType.slice(1)} template applied!`, severity: 'success' });
  };

  // Copy selected element(s)
  const copySelected = () => {
    if (selectedElement) {
      setClipboard([{ ...selectedElement }]);
      setSnackbar({ open: true, message: 'Element copied!', severity: 'info' });
    }
  };

  // Paste element(s)
  const pasteElement = async () => {
    if (clipboard.length === 0) return;

    const newIds: string[] = [];
    const newElements: WhiteboardElement[] = [];
    
    // Calculate offset based on first element to maintain relative positions
    const baseX = clipboard[0].x;
    const baseY = clipboard[0].y;
    
    for (let i = 0; i < clipboard.length; i++) {
      const el = clipboard[i];
      const newElement: WhiteboardElement = {
        ...el,
        element_id: generateElementId(),
        x: el.x - baseX + baseX + 20, // Offset from base position
        y: el.y - baseY + baseY + 20,
        z_index: elements.length + i,
      };
      newElements.push(newElement);
      newIds.push(newElement.element_id);
    }

    setElements(prev => [...prev, ...newElements]);
    
    // Send WebSocket messages and persist
    for (const newElement of newElements) {
      sendWsMessage({ type: 'create', element: newElement });
      try {
        await whiteboardClient.createElement(Number(whiteboardId), {
          element_id: newElement.element_id,
          element_type: newElement.element_type,
          x: newElement.x,
          y: newElement.y,
          width: newElement.width,
          height: newElement.height,
          rotation: newElement.rotation,
          fill_color: newElement.fill_color,
          stroke_color: newElement.stroke_color,
          stroke_width: newElement.stroke_width,
          opacity: newElement.opacity,
          content: newElement.content,
          font_size: newElement.font_size,
          points: newElement.points,
          z_index: newElement.z_index,
        });
      } catch (error) {
        console.error('Failed to paste element:', error);
      }
    }

    if (newElements.length === 1) {
      setSelectedElement(newElements[0]);
      setMultiSelection([]);
    } else {
      setSelectedElement(null);
      setMultiSelection(newIds);
    }
    setSnackbar({ open: true, message: `Pasted ${newElements.length > 1 ? newElements.length + ' elements' : 'element'}!`, severity: 'info' });
  };

  // Reset view
  const resetView = () => {
    setZoom(1);
    setPanOffset({ x: 0, y: 0 });
  };

  // Layer ordering functions
  const bringToFront = async () => {
    if (!selectedElement) return;
    const maxZ = Math.max(...elements.map(e => e.z_index || 0));
    const updatedElement = { ...selectedElement, z_index: maxZ + 1 };
    
    setElements(prev => prev.map(e => 
      e.element_id === selectedElement.element_id ? updatedElement : e
    ));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, { z_index: maxZ + 1 });
    } catch (error) {
      console.error('Failed to update layer order:', error);
    }
    setSnackbar({ open: true, message: 'Moved to front!', severity: 'info' });
  };

  const sendToBack = async () => {
    if (!selectedElement) return;
    const minZ = Math.min(...elements.map(e => e.z_index || 0));
    const updatedElement = { ...selectedElement, z_index: minZ - 1 };
    
    setElements(prev => prev.map(e => 
      e.element_id === selectedElement.element_id ? updatedElement : e
    ));
    setSelectedElement(updatedElement);
    sendWsMessage({ type: 'update', element: updatedElement });
    
    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, { z_index: minZ - 1 });
    } catch (error) {
      console.error('Failed to update layer order:', error);
    }
    setSnackbar({ open: true, message: 'Sent to back!', severity: 'info' });
  };

  const bringForward = async () => {
    if (!selectedElement) return;
    const currentZ = selectedElement.z_index || 0;
    const nextHigher = elements
      .filter(e => (e.z_index || 0) > currentZ)
      .sort((a, b) => (a.z_index || 0) - (b.z_index || 0))[0];
    
    if (nextHigher) {
      const updatedCurrent = { ...selectedElement, z_index: nextHigher.z_index || 0 };
      const updatedNext = { ...nextHigher, z_index: currentZ };
      
      setElements(prev => prev.map(e => {
        if (e.element_id === selectedElement.element_id) return updatedCurrent;
        if (e.element_id === nextHigher.element_id) return updatedNext;
        return e;
      }));
      setSelectedElement(updatedCurrent);
      sendWsMessage({ type: 'update', element: updatedCurrent });
      sendWsMessage({ type: 'update', element: updatedNext });
      
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, { z_index: nextHigher.z_index || 0 });
        await whiteboardClient.updateElement(Number(whiteboardId), nextHigher.element_id, { z_index: currentZ });
      } catch (error) {
        console.error('Failed to update layer order:', error);
      }
    }
  };

  const sendBackward = async () => {
    if (!selectedElement) return;
    const currentZ = selectedElement.z_index || 0;
    const nextLower = elements
      .filter(e => (e.z_index || 0) < currentZ)
      .sort((a, b) => (b.z_index || 0) - (a.z_index || 0))[0];
    
    if (nextLower) {
      const updatedCurrent = { ...selectedElement, z_index: nextLower.z_index || 0 };
      const updatedNext = { ...nextLower, z_index: currentZ };
      
      setElements(prev => prev.map(e => {
        if (e.element_id === selectedElement.element_id) return updatedCurrent;
        if (e.element_id === nextLower.element_id) return updatedNext;
        return e;
      }));
      setSelectedElement(updatedCurrent);
      sendWsMessage({ type: 'update', element: updatedCurrent });
      sendWsMessage({ type: 'update', element: updatedNext });
      
      try {
        await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, { z_index: nextLower.z_index || 0 });
        await whiteboardClient.updateElement(Number(whiteboardId), nextLower.element_id, { z_index: currentZ });
      } catch (error) {
        console.error('Failed to update layer order:', error);
      }
    }
  };

  // Image upload handler
  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
      setSnackbar({ open: true, message: 'Please select an image file', severity: 'error' });
      return;
    }

    // Read as data URL
    const reader = new FileReader();
    reader.onload = async (event) => {
      const dataUrl = event.target?.result as string;
      
      // Create image to get dimensions
      const img = new Image();
      img.onload = async () => {
        const maxSize = 400;
        let width = img.width;
        let height = img.height;
        
        // Scale down if too large
        if (width > maxSize || height > maxSize) {
          const ratio = Math.min(maxSize / width, maxSize / height);
          width *= ratio;
          height *= ratio;
        }

        const newElement: WhiteboardElement = {
          element_id: generateElementId(),
          element_type: 'image',
          x: (whiteboard?.canvas_width || 1920) / 2 - width / 2,
          y: (whiteboard?.canvas_height || 1080) / 2 - height / 2,
          width,
          height,
          rotation: 0,
          fill_color: null,
          stroke_color: 'transparent',
          stroke_width: 0,
          opacity: 1,
          content: dataUrl,
          z_index: elements.length,
        };

        setElements(prev => [...prev, newElement]);
        sendWsMessage({ type: 'create', element: newElement });

        try {
          await whiteboardClient.createElement(Number(whiteboardId), {
            element_id: newElement.element_id,
            element_type: newElement.element_type,
            x: newElement.x,
            y: newElement.y,
            width: newElement.width,
            height: newElement.height,
            rotation: newElement.rotation,
            fill_color: newElement.fill_color,
            stroke_color: newElement.stroke_color,
            stroke_width: newElement.stroke_width,
            opacity: newElement.opacity,
            content: newElement.content,
            z_index: newElement.z_index,
          });
        } catch (error) {
          console.error('Failed to save image:', error);
        }

        setSelectedElement(newElement);
        setSnackbar({ open: true, message: 'Image added!', severity: 'success' });
      };
      img.src = dataUrl;
    };
    reader.readAsDataURL(file);
    
    // Reset input
    if (imageInputRef.current) {
      imageInputRef.current.value = '';
    }
  };

  // Update element opacity
  const updateElementOpacity = async (newOpacity: number) => {
    if (!selectedElement) return;
    
    const updatedElement = { ...selectedElement, opacity: newOpacity };
    setElements(prev => prev.map(e => 
      e.element_id === selectedElement.element_id ? updatedElement : e
    ));
    setSelectedElement(updatedElement);
    setElementOpacity(newOpacity);
    sendWsMessage({ type: 'update', element: updatedElement });

    try {
      await whiteboardClient.updateElement(Number(whiteboardId), selectedElement.element_id, { opacity: newOpacity });
    } catch (error) {
      console.error('Failed to update opacity:', error);
    }
  };

  // Snap coordinate to grid
  const snapToGridCoord = (value: number) => {
    if (!snapToGrid) return value;
    return Math.round(value / GRID_SIZE) * GRID_SIZE;
  };

  // Duplicate element
  const duplicateElement = async () => {
    if (!selectedElement) return;
    
    const newElement: WhiteboardElement = {
      ...selectedElement,
      element_id: generateElementId(),
      x: snapToGridCoord(selectedElement.x + 20),
      y: snapToGridCoord(selectedElement.y + 20),
      z_index: elements.length,
    };

    setElements(prev => [...prev, newElement]);
    sendWsMessage({ type: 'create', element: newElement });

    try {
      await whiteboardClient.createElement(Number(whiteboardId), {
        element_id: newElement.element_id,
        element_type: newElement.element_type,
        x: newElement.x,
        y: newElement.y,
        width: newElement.width,
        height: newElement.height,
        rotation: newElement.rotation,
        fill_color: newElement.fill_color,
        stroke_color: newElement.stroke_color,
        stroke_width: newElement.stroke_width,
        opacity: newElement.opacity,
        content: newElement.content,
        font_size: newElement.font_size,
        points: newElement.points,
        z_index: newElement.z_index,
      });
    } catch (error) {
      console.error('Failed to duplicate element:', error);
    }

    setSelectedElement(newElement);
    setSnackbar({ open: true, message: 'Element duplicated!', severity: 'info' });
  };

  // Select all elements
  const selectAll = () => {
    const allIds = elements.map(e => e.element_id);
    setMultiSelection(allIds);
    setSelectedElement(null);
    setSnackbar({ open: true, message: `Selected ${allIds.length} elements`, severity: 'info' });
  };

  // Clear multi-selection
  const clearSelection = () => {
    setMultiSelection([]);
    setSelectedElement(null);
  };

  // Delete multiple selected elements
  const deleteMultiSelection = async () => {
    if (multiSelection.length === 0) return;
    
    // Filter out locked elements and compute remaining elements
    const idsToDelete = multiSelection.filter(id => !lockedElements.has(id));
    const remainingElements = elements.filter(el => !idsToDelete.includes(el.element_id));
    
    // Update elements state once
    setElements(remainingElements);
    
    // Delete from server
    for (const elementId of idsToDelete) {
      sendWsMessage({ type: 'delete', element_id: elementId });
      
      try {
        await whiteboardClient.deleteElement(Number(whiteboardId), elementId);
      } catch (error) {
        console.error('Failed to delete element:', error);
      }
    }
    
    // Update history
    setHistory(prev => [...prev.slice(0, historyIndex + 1), remainingElements]);
    setHistoryIndex(prev => prev + 1);
    
    setMultiSelection([]);
    setSnackbar({ open: true, message: `Deleted ${idsToDelete.length} elements`, severity: 'info' });
  };

  // Toggle element lock
  const toggleLock = () => {
    if (!selectedElement) return;
    
    const newLocked = new Set(lockedElements);
    if (newLocked.has(selectedElement.element_id)) {
      newLocked.delete(selectedElement.element_id);
      setSnackbar({ open: true, message: 'Element unlocked', severity: 'info' });
    } else {
      newLocked.add(selectedElement.element_id);
      setSnackbar({ open: true, message: 'Element locked', severity: 'info' });
    }
    setLockedElements(newLocked);
  };

  // Zoom to fit all elements
  const zoomToFit = () => {
    if (elements.length === 0) {
      resetView();
      return;
    }

    const bounds = elements.reduce(
      (acc, el) => ({
        minX: Math.min(acc.minX, el.x),
        minY: Math.min(acc.minY, el.y),
        maxX: Math.max(acc.maxX, el.x + el.width),
        maxY: Math.max(acc.maxY, el.y + el.height),
      }),
      { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity }
    );

    const container = containerRef.current;
    if (!container) return;

    const contentWidth = bounds.maxX - bounds.minX + 100; // Add padding
    const contentHeight = bounds.maxY - bounds.minY + 100;
    const containerWidth = container.clientWidth;
    const containerHeight = container.clientHeight;

    const scaleX = containerWidth / contentWidth;
    const scaleY = containerHeight / contentHeight;
    const newZoom = Math.min(scaleX, scaleY, 2); // Cap at 2x

    const centerX = (bounds.minX + bounds.maxX) / 2;
    const centerY = (bounds.minY + bounds.maxY) / 2;

    setZoom(newZoom);
    setPanOffset({
      x: containerWidth / 2 - centerX * newZoom,
      y: containerHeight / 2 - centerY * newZoom,
    });
    setSnackbar({ open: true, message: 'Zoomed to fit content', severity: 'info' });
  };

  // Toggle fullscreen mode
  const toggleFullscreen = useCallback(() => {
    if (!document.fullscreenElement) {
      containerRef.current?.parentElement?.requestFullscreen?.().then(() => {
        setIsFullscreen(true);
        setSnackbar({ open: true, message: 'Entered fullscreen mode (F11 to exit)', severity: 'info' });
      }).catch(err => {
        console.error('Failed to enter fullscreen:', err);
      });
    } else {
      document.exitFullscreen?.().then(() => {
        setIsFullscreen(false);
        setSnackbar({ open: true, message: 'Exited fullscreen mode', severity: 'info' });
      }).catch(err => {
        console.error('Failed to exit fullscreen:', err);
      });
    }
  }, []);

  // Listen for fullscreen change events
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };
    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => document.removeEventListener('fullscreenchange', handleFullscreenChange);
  }, []);

  // Handle double-click for text editing
  const handleDoubleClick = async (e: React.MouseEvent) => {
    const coords = getCanvasCoords(e);
    const clickedElement = [...elements].reverse().find(el => {
      return (
        coords.x >= el.x &&
        coords.x <= el.x + el.width &&
        coords.y >= el.y &&
        coords.y <= el.y + el.height
      );
    });

    if (clickedElement) {
      if (lockedElements.has(clickedElement.element_id)) return;

      // Text and sticky notes - edit content
      if (clickedElement.element_type === 'text' || clickedElement.element_type === 'sticky') {
        // Store element position in ref to prevent flickering
        editingElementRef.current = {
          x: clickedElement.x,
          y: clickedElement.y,
          width: clickedElement.width,
          height: clickedElement.height,
          fill_color: clickedElement.fill_color,
          stroke_color: clickedElement.stroke_color,
          font_size: clickedElement.font_size,
          element_type: clickedElement.element_type,
        };
        setEditingTextId(clickedElement.element_id);
        setEditingText(clickedElement.content || '');
        setTimeout(() => textInputRef.current?.focus(), 0);
      }
      // Code blocks - edit code content
      else if (clickedElement.element_type === 'code') {
        const newCode = prompt('Enter code:', clickedElement.content || '// Your code here');
        if (newCode !== null) {
          const updatedElement = { ...clickedElement, content: newCode };
          setElements(prev => prev.map(e => 
            e.element_id === clickedElement.element_id ? updatedElement : e
          ));
          sendWsMessage({ type: 'update', element: updatedElement });
          
          try {
            await whiteboardClient.updateElement(Number(whiteboardId), clickedElement.element_id, { content: newCode });
          } catch (error) {
            console.error('Failed to update code:', error);
          }
          
          setSnackbar({ open: true, message: 'Code updated', severity: 'success' });
        }
      }
      // Checklist - add new item on double-click
      else if (clickedElement.element_type === 'checklist') {
        addChecklistItem(clickedElement);
      }
      // Table - edit cell on double-click
      else if (clickedElement.element_type === 'table') {
        const cell = getTableCellAtPosition(clickedElement, coords.x, coords.y);
        if (cell) {
          startEditingTableCell(clickedElement, cell.row, cell.col);
        }
      }
      // Link elements - open link in new tab
      else if (clickedElement.element_type === 'link') {
        openLinkInNewTab(clickedElement);
      }
      // Shapes and symbols - edit label
      else if (['rectangle', 'ellipse', 'symbol'].includes(clickedElement.element_type)) {
        const newLabel = prompt('Enter label for this element:', clickedElement.label || '');
        if (newLabel !== null) {
          const updatedElement = { ...clickedElement, label: newLabel || undefined };
          setElements(prev => prev.map(e => 
            e.element_id === clickedElement.element_id ? updatedElement : e
          ));
          sendWsMessage({ type: 'update', element: updatedElement });
          
          try {
            await whiteboardClient.updateElement(Number(whiteboardId), clickedElement.element_id, { label: newLabel || undefined });
          } catch (error) {
            console.error('Failed to update label:', error);
          }
          
          setSnackbar({ open: true, message: 'Label updated', severity: 'success' });
        }
      }
    }
  };

  // Save text edit
  const saveTextEdit = async () => {
    if (!editingTextId) return;
    
    const element = elements.find(e => e.element_id === editingTextId);
    if (!element) return;

    const updatedElement = { ...element, content: editingText };
    setElements(prev => prev.map(e => 
      e.element_id === editingTextId ? updatedElement : e
    ));
    sendWsMessage({ type: 'update', element: updatedElement });

    try {
      await whiteboardClient.updateElement(Number(whiteboardId), editingTextId, { content: editingText });
    } catch (error) {
      console.error('Failed to update text:', error);
    }

    editingElementRef.current = null;
    setEditingTextId(null);
    setEditingText('');
  };

  // Alignment functions for multi-selection
  const alignElements = async (alignment: 'left' | 'center' | 'right' | 'top' | 'middle' | 'bottom') => {
    if (multiSelection.length < 2) return;
    
    const selectedEls = elements.filter(e => multiSelection.includes(e.element_id));
    const bounds = selectedEls.reduce(
      (acc, el) => ({
        minX: Math.min(acc.minX, el.x),
        minY: Math.min(acc.minY, el.y),
        maxX: Math.max(acc.maxX, el.x + el.width),
        maxY: Math.max(acc.maxY, el.y + el.height),
      }),
      { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity }
    );

    const centerX = (bounds.minX + bounds.maxX) / 2;
    const centerY = (bounds.minY + bounds.maxY) / 2;

    for (const el of selectedEls) {
      if (lockedElements.has(el.element_id)) continue;
      
      let newX = el.x;
      let newY = el.y;

      switch (alignment) {
        case 'left': newX = bounds.minX; break;
        case 'center': newX = centerX - el.width / 2; break;
        case 'right': newX = bounds.maxX - el.width; break;
        case 'top': newY = bounds.minY; break;
        case 'middle': newY = centerY - el.height / 2; break;
        case 'bottom': newY = bounds.maxY - el.height; break;
      }

      const updatedElement = { ...el, x: snapToGridCoord(newX), y: snapToGridCoord(newY) };
      setElements(prev => prev.map(e => 
        e.element_id === el.element_id ? updatedElement : e
      ));
      sendWsMessage({ type: 'update', element: updatedElement });

      try {
        await whiteboardClient.updateElement(Number(whiteboardId), el.element_id, { x: updatedElement.x, y: updatedElement.y });
      } catch (error) {
        console.error('Failed to align element:', error);
      }
    }

    setSnackbar({ open: true, message: `Aligned ${selectedEls.length} elements`, severity: 'info' });
  };

  // Timer animation effect - trigger re-render every second when timers are running
  useEffect(() => {
    const hasRunningTimers = elements.some(el => 
      el.element_type === 'timer' && 
      el.timer_started_at && 
      !el.timer_paused_at &&
      el.timer_duration
    );

    if (!hasRunningTimers) return;

    const interval = setInterval(() => {
      // Force re-render by updating a trivial state, the canvas will redraw
      setElements(prev => [...prev]);
    }, 1000);

    return () => clearInterval(interval);
  }, [elements]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't handle shortcuts when typing in inputs
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      
      // Don't handle shortcuts when editing text
      if (editingTextId) {
        if (e.key === 'Escape') {
          editingElementRef.current = null;
          setEditingTextId(null);
          setEditingText('');
        }
        // Don't intercept other keys when editing
        return;
      }

      // Delete selected element
      if (e.key === 'Delete' || e.key === 'Backspace') {
        if (multiSelection.length > 0) {
          e.preventDefault();
          deleteMultiSelection();
        } else if (selectedElement) {
          e.preventDefault();
          deleteSelected();
        }
      }

      // Undo: Ctrl+Z
      if (e.ctrlKey && e.key === 'z' && !e.shiftKey) {
        e.preventDefault();
        undo();
      }

      // Redo: Ctrl+Y or Ctrl+Shift+Z
      if ((e.ctrlKey && e.key === 'y') || (e.ctrlKey && e.shiftKey && e.key === 'z')) {
        e.preventDefault();
        redo();
      }

      // Copy: Ctrl+C
      if (e.ctrlKey && e.key === 'c') {
        if (selectedElement || multiSelection.length > 0) {
          e.preventDefault();
          if (multiSelection.length > 0) {
            // Copy all selected elements
            const selectedEls = elements.filter(el => multiSelection.includes(el.element_id));
            if (selectedEls.length > 0) {
              setClipboard(selectedEls.map(el => ({ ...el })));
              setSnackbar({ open: true, message: `Copied ${selectedEls.length > 1 ? selectedEls.length + ' elements' : 'element'}!`, severity: 'info' });
            }
          } else {
            copySelected();
          }
        }
      }

      // Paste: Ctrl+V
      if (e.ctrlKey && e.key === 'v') {
        if (clipboard.length > 0) {
          e.preventDefault();
          pasteElement();
        }
      }

      // Duplicate: Ctrl+D
      if (e.ctrlKey && e.key === 'd') {
        e.preventDefault();
        if (multiSelection.length > 0) {
          // Duplicate all selected elements
          const selectedEls = elements.filter(el => multiSelection.includes(el.element_id));
          const newIds: string[] = [];
          selectedEls.forEach(el => {
            const newElement: WhiteboardElement = {
              ...el,
              element_id: generateElementId(),
              x: el.x + 20,
              y: el.y + 20,
              z_index: elements.length + newIds.length,
            };
            setElements(prev => [...prev, newElement]);
            sendWsMessage({ type: 'create', element: newElement });
            whiteboardClient.createElement(Number(whiteboardId), newElement).catch(console.error);
            newIds.push(newElement.element_id);
          });
          setMultiSelection(newIds);
          setSnackbar({ open: true, message: `Duplicated ${selectedEls.length} elements!`, severity: 'info' });
        } else if (selectedElement) {
          duplicateElement();
        }
      }

      // Select All: Ctrl+A
      if (e.ctrlKey && e.key === 'a') {
        e.preventDefault();
        selectAll();
      }

      // Lock/Unlock: Ctrl+L
      if (e.ctrlKey && e.key === 'l') {
        if (selectedElement) {
          e.preventDefault();
          toggleLock();
        }
      }

      // Escape: Deselect
      if (e.key === 'Escape') {
        setSelectedElement(null);
        setMultiSelection([]);
        setSelectedTool('select');
      }

      // Tool shortcuts (only when Ctrl/Cmd not pressed to avoid conflicts)
      if (!e.ctrlKey && !e.metaKey) {
        if (e.key === 'v' || e.key === '1') setSelectedTool('select');
        if (e.key === 'h' || e.key === '2') setSelectedTool('pan');
        if (e.key === 'r' || e.key === '3') setSelectedTool('rectangle');
        if (e.key === 'o' || e.key === '4') setSelectedTool('ellipse');
        if (e.key === 'l' || e.key === '5') setSelectedTool('line');
        if (e.key === 'a' || e.key === '6') setSelectedTool('arrow');
        if (e.key === 't' || e.key === '7') setSelectedTool('text');
        if (e.key === 's' || e.key === '8') setSelectedTool('sticky');
        if (e.key === 'p' || e.key === '9') setSelectedTool('freehand');
        if (e.key === 'e') setSelectedTool('eraser');
      }

      // Grid toggle: G
      if (e.key === 'g' && !e.ctrlKey) {
        setShowGrid(prev => !prev);
      }

      // Snap to grid toggle: Shift+G
      if (e.key === 'G' && e.shiftKey) {
        setSnapToGrid(prev => !prev);
        setSnackbar({ open: true, message: `Snap to grid ${!snapToGrid ? 'enabled' : 'disabled'}`, severity: 'info' });
      }

      // Reset view: Home or 0
      if (e.key === 'Home' || e.key === '0') {
        resetView();
      }

      // Zoom to fit: F
      if (e.key === 'f' && !e.ctrlKey) {
        zoomToFit();
      }

      // Fullscreen toggle: F11
      if (e.key === 'F11') {
        e.preventDefault();
        toggleFullscreen();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedElement, historyIndex, history, clipboard, multiSelection, editingTextId, snapToGrid]);

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh', bgcolor: '#1e1e2e' }}>
      {/* Top Toolbar */}
      <Paper
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          p: 1,
          bgcolor: alpha('#1e1e2e', 0.95),
          borderBottom: `1px solid ${alpha('#ffffff', 0.1)}`,
        }}
      >
        <Tooltip title="Back to Project">
          <IconButton onClick={() => navigate(`/projects/${projectId}`)}>
            <ChevronLeftIcon />
          </IconButton>
        </Tooltip>

        <Typography variant="h6" sx={{ ml: 1, mr: 2 }}>
          {whiteboard?.name || 'Whiteboard'}
        </Typography>

        <Divider orientation="vertical" flexItem />

        {/* Tool buttons */}
        <ToggleButtonGroup
          value={selectedTool}
          exclusive
          onChange={(_, value) => value && setSelectedTool(value)}
          size="small"
        >
          <Tooltip title="Select (V)"><ToggleButton value="select"><MouseIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Pan (H)"><ToggleButton value="pan"><PanToolIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Rectangle (R)"><ToggleButton value="rectangle"><CropSquareIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Ellipse (O)"><ToggleButton value="ellipse"><CircleOutlinedIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Triangle"><ToggleButton value="triangle"><ChangeHistoryIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Diamond"><ToggleButton value="diamond"><DiamondIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Hexagon"><ToggleButton value="hexagon"><HexagonIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Star"><ToggleButton value="star"><StarIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Line (L)"><ToggleButton value="line"><RemoveIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Arrow (A)"><ToggleButton value="arrow"><ArrowForwardIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Bidirectional Arrow"><ToggleButton value="bidirectional_arrow"><SyncAltIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Text (T)"><ToggleButton value="text"><TextFieldsIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Sticky Note (S)"><ToggleButton value="sticky"><StickyNote2Icon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Timer - Countdown for Timeboxing"><ToggleButton value="timer"><TimerIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Table"><ToggleButton value="table"><TableChartOutlinedIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Code Block"><ToggleButton value="code"><CodeIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Checklist"><ToggleButton value="checklist"><ChecklistIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Link/URL Card"><ToggleButton value="link"><LaunchIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Smart Connector - Connect Elements"><ToggleButton value="connector"><LinkIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Pencil (P)"><ToggleButton value="freehand"><CreateIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
          <Tooltip title="Eraser - Click to Delete (E)"><ToggleButton value="eraser"><AutoFixOffIcon sx={{ fontSize: 18 }} /></ToggleButton></Tooltip>
        </ToggleButtonGroup>

        <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

        {/* Sticky Note Colors */}
        <Tooltip title="Sticky Note Colors">
          <IconButton
            onClick={(e) => setStickyColorAnchor(e.currentTarget)}
            sx={{ 
              border: '1px solid transparent',
              '&:hover': { bgcolor: alpha('#fef08a', 0.2) }
            }}
          >
            <Box sx={{ 
              width: 20, height: 20, borderRadius: 0.5,
              background: 'linear-gradient(135deg, #fef08a 0%, #fda4af 50%, #93c5fd 100%)',
              border: '1px solid #999'
            }} />
          </IconButton>
        </Tooltip>

        {/* Gradient Fill */}
        <Tooltip title="Gradient Fill">
          <IconButton
            onClick={() => setGradientDialogOpen(true)}
            disabled={!selectedElement || !['rectangle', 'ellipse', 'triangle', 'diamond', 'hexagon', 'star'].includes(selectedElement.element_type)}
            sx={{ '&:hover': { bgcolor: alpha('#8b5cf6', 0.1) } }}
          >
            <GradientIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Font Selection */}
        <Tooltip title="Font">
          <IconButton
            onClick={(e) => setFontMenuAnchor(e.currentTarget)}
            disabled={!selectedElement || !['text', 'sticky'].includes(selectedElement.element_type)}
            sx={{ '&:hover': { bgcolor: alpha('#3b82f6', 0.1) } }}
          >
            <FontDownloadIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Text Formatting (when text/sticky selected) */}
        {selectedElement && ['text', 'sticky'].includes(selectedElement.element_type) && (
          <>
            <Tooltip title="Bold">
              <IconButton
                onClick={() => toggleTextFormat('bold')}
                color={selectedElement.text_bold ? 'primary' : 'default'}
                size="small"
              >
                <FormatBoldIcon sx={{ fontSize: 18 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Italic">
              <IconButton
                onClick={() => toggleTextFormat('italic')}
                color={selectedElement.text_italic ? 'primary' : 'default'}
                size="small"
              >
                <FormatItalicIcon sx={{ fontSize: 18 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Underline">
              <IconButton
                onClick={() => toggleTextFormat('underline')}
                color={selectedElement.text_underline ? 'primary' : 'default'}
                size="small"
              >
                <FormatUnderlinedIcon sx={{ fontSize: 18 }} />
              </IconButton>
            </Tooltip>
          </>
        )}

        <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

        {/* Search */}
        <Tooltip title="Search Elements">
          <IconButton
            onClick={() => setSearchOpen(true)}
            sx={{ '&:hover': { bgcolor: alpha('#3b82f6', 0.1) } }}
          >
            <SearchIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* AI Features */}
        <Tooltip title="AI Features (Summarize, Categorize, Generate)">
          <IconButton
            onClick={() => { setAiDialogOpen(true); setAiDialogMode('summarize'); setAiResult(''); }}
            sx={{ 
              '&:hover': { bgcolor: alpha('#8b5cf6', 0.1) },
              color: '#8b5cf6'
            }}
          >
            <AutoFixHighIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Network Symbols Button */}
        <Tooltip title="Network Symbols">
          <IconButton
            onClick={(e) => setSymbolsAnchor(e.currentTarget)}
            color={selectedTool === 'symbol' ? 'primary' : 'default'}
            sx={{ 
              border: selectedTool === 'symbol' ? '2px solid #3b82f6' : '1px solid transparent',
              bgcolor: selectedTool === 'symbol' ? alpha('#3b82f6', 0.1) : 'transparent'
            }}
          >
            <CategoryIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Templates Button */}
        <Tooltip title="Templates (Retro, SWOT, Mind Map, Risk Matrix)">
          <IconButton
            onClick={() => setTemplatesDialogOpen(true)}
            sx={{ 
              border: '1px solid transparent',
              '&:hover': { bgcolor: alpha('#8b5cf6', 0.1) }
            }}
          >
            <DashboardCustomizeIcon sx={{ fontSize: 20, color: '#8b5cf6' }} />
          </IconButton>
        </Tooltip>

        <Divider orientation="vertical" flexItem sx={{ mx: 0.5 }} />

        {/* Snap to Grid Toggle */}
        <Tooltip title={snapToGrid ? "Snap to Grid: ON" : "Snap to Grid: OFF"}>
          <IconButton
            onClick={() => setSnapToGrid(!snapToGrid)}
            color={snapToGrid ? 'primary' : 'default'}
            sx={{ 
              border: snapToGrid ? '2px solid #3b82f6' : '1px solid transparent',
              bgcolor: snapToGrid ? alpha('#3b82f6', 0.1) : 'transparent'
            }}
          >
            <GridViewIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Group Selected Elements */}
        <Tooltip title="Group Selected Elements">
          <IconButton
            onClick={groupSelectedElements}
            disabled={multiSelection.length < 2}
            sx={{ '&:hover': { bgcolor: alpha('#8b5cf6', 0.1) } }}
          >
            <GroupWorkIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Ungroup Elements */}
        <Tooltip title="Ungroup Elements">
          <IconButton
            onClick={ungroupSelectedElements}
            disabled={!selectedElement?.group_id && multiSelection.length === 0}
            sx={{ '&:hover': { bgcolor: alpha('#f97316', 0.1) } }}
          >
            <LinkOffIcon sx={{ fontSize: 20 }} />
          </IconButton>
        </Tooltip>

        {/* Sticky Note Size (when sticky selected) */}
        {selectedElement && selectedElement.element_type === 'sticky' && (
          <Tooltip title="Sticky Note Size">
            <IconButton
              onClick={(e) => setStickySizeMenuAnchor(e.currentTarget)}
              sx={{ '&:hover': { bgcolor: alpha('#fef08a', 0.2) } }}
            >
              <AspectRatioIcon sx={{ fontSize: 20 }} />
            </IconButton>
          </Tooltip>
        )}

        {/* Comments Panel */}
        <Tooltip title="Comments">
          <IconButton
            onClick={() => {
              if (selectedElement) {
                setCommentingElement(selectedElement);
                setCommentsPanelOpen(true);
              } else {
                setSnackbar({ open: true, message: 'Select an element to view comments', severity: 'info' });
              }
            }}
            sx={{ 
              '&:hover': { bgcolor: alpha('#3b82f6', 0.1) },
              position: 'relative'
            }}
          >
            <CommentIcon sx={{ fontSize: 20 }} />
            {selectedElement?.comments && selectedElement.comments.length > 0 && (
              <Box sx={{
                position: 'absolute',
                top: 2,
                right: 2,
                width: 14,
                height: 14,
                borderRadius: '50%',
                bgcolor: '#ef4444',
                color: 'white',
                fontSize: 10,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}>
                {selectedElement.comments.length}
              </Box>
            )}
          </IconButton>
        </Tooltip>

        {/* Sticky Color Popover */}
        <Popover
          open={Boolean(stickyColorAnchor)}
          anchorEl={stickyColorAnchor}
          onClose={() => setStickyColorAnchor(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        >
          <Box sx={{ p: 2, width: 200 }}>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>Sticky Note Colors</Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {STICKY_COLORS.map(({ name, color }) => (
                <Tooltip key={color} title={name}>
                  <IconButton
                    size="small"
                    onClick={() => {
                      setSelectedStickyColor(color);
                      setFillColor(color);
                      setStickyColorAnchor(null);
                      setSnackbar({ open: true, message: `${name} sticky selected`, severity: 'info' });
                    }}
                    sx={{
                      width: 36, height: 36,
                      bgcolor: color,
                      border: selectedStickyColor === color ? '2px solid #3b82f6' : '1px solid #ccc',
                      '&:hover': { bgcolor: color, opacity: 0.8 }
                    }}
                  />
                </Tooltip>
              ))}
            </Box>
          </Box>
        </Popover>

        {/* Font Menu */}
        <Menu
          anchorEl={fontMenuAnchor}
          open={Boolean(fontMenuAnchor)}
          onClose={() => setFontMenuAnchor(null)}
        >
          {FONT_OPTIONS.map(({ name, value }) => (
            <MenuItem
              key={value}
              onClick={() => applyFont(value)}
              selected={selectedElement?.font_family === value}
              sx={{ fontFamily: value }}
            >
              {name}
            </MenuItem>
          ))}
        </Menu>

        {/* Symbols Popover */}
        <Popover
          open={Boolean(symbolsAnchor)}
          anchorEl={symbolsAnchor}
          onClose={() => setSymbolsAnchor(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
          transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        >
          <Box sx={{ p: 2, maxWidth: 420, maxHeight: '70vh', overflow: 'auto' }}>
            <Typography variant="subtitle2" sx={{ mb: 1, color: 'text.secondary' }}>
              Symbols Library
            </Typography>
            <Typography variant="caption" sx={{ display: 'block', mb: 2, color: 'text.disabled' }}>
              Select a symbol, then click on canvas to place it
            </Typography>
            
            {/* Group symbols by category */}
            {['network', 'security', 'server', 'database', 'framework', 'mobile', 'endpoint', 'hardware', 'cloud', 'ai'].map(category => {
              const categorySymbols = NETWORK_SYMBOLS.filter(s => s.category === category);
              if (categorySymbols.length === 0) return null;
              
              const categoryLabels: Record<string, string> = {
                network: '🌐 Network',
                security: '🔒 Security',
                server: '🖥️ Servers & Backend',
                database: '🗄️ Databases',
                framework: '⚛️ Frameworks & Languages',
                mobile: '📱 Mobile & Devices',
                endpoint: '💻 Endpoints',
                hardware: '🔧 Hardware',
                cloud: '☁️ Cloud',
                ai: '🤖 AI/LLM Providers'
              };
              
              return (
                <Box key={category} sx={{ mb: 2 }}>
                  <Typography variant="caption" sx={{ color: 'text.secondary', fontWeight: 600 }}>
                    {categoryLabels[category] || category}
                  </Typography>
                  <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 0.5, mt: 0.5 }}>
                    {categorySymbols.map(symbol => {
                      const IconComponent = {
                        // Network
                        router: RouterIcon,
                        switch: HubIcon,
                        hub: HubIcon,
                        wireless_ap: WifiIcon,
                        vpn: VpnKeyIcon,
                        loadbalancer: NetworkCheckIcon,
                        cellular: SignalCellularAltIcon,
                        wifi_signal: SignalWifi4BarIcon,
                        wifi_off: WifiOffIcon,
                        '4g': FourGMobiledataIcon,
                        '5g': FiveGIcon,
                        satellite: SatelliteAltIcon,
                        ethernet: CableIcon,
                        gps: GpsFixedIcon,
                        // Security
                        firewall: SecurityIcon,
                        lock: LockIcon,
                        key: VpnKeyIcon,
                        bug: BugReportIcon,
                        // Servers
                        server: StorageIcon,
                        web_server: HttpIcon,
                        api: ApiIcon,
                        nodejs: IntegrationInstructionsIcon,
                        php: CodeIcon,
                        python: CodeIcon,
                        java: CodeIcon,
                        docker: DeveloperBoardIcon,
                        kubernetes: HubIcon,
                        linux: TerminalIcon,
                        windows_server: ComputerIcon,
                        nginx: HttpIcon,
                        apache: HttpIcon,
                        kafka: DataUsageIcon,
                        rabbitmq: DataUsageIcon,
                        grafana: AnalyticsIcon,
                        prometheus: SpeedIcon,
                        // Databases
                        database: DnsIcon,
                        mysql: TableChartIcon,
                        postgresql: TableChartIcon,
                        mongodb: DataObjectIcon,
                        redis: MemoryIcon,
                        sql: TableChartIcon,
                        elasticsearch: RadarIcon,
                        cassandra: DataUsageIcon,
                        sqlite: TableChartIcon,
                        firebase: ElectricBoltIcon,
                        // Frameworks
                        react: IntegrationInstructionsIcon,
                        vue: IntegrationInstructionsIcon,
                        angular: IntegrationInstructionsIcon,
                        vite: BuildIcon,
                        nextjs: WebIcon,
                        typescript: CodeIcon,
                        javascript: JavascriptIcon,
                        html: WebIcon,
                        css: WebIcon,
                        go: CodeIcon,
                        rust: HexagonIcon,
                        csharp: CodeIcon,
                        cpp: CodeIcon,
                        ruby: TokenIcon,
                        swift: AppleIcon,
                        kotlin: CodeIcon,
                        flutter: PhoneAndroidIcon,
                        svelte: IntegrationInstructionsIcon,
                        graphql: HexagonIcon,
                        // Mobile
                        iphone: PhoneIphoneIcon,
                        ios: AppleIcon,
                        android: AndroidIcon,
                        tablet: TabletIcon,
                        smartwatch: WatchIcon,
                        // Endpoints
                        pc: ComputerIcon,
                        laptop: LaptopIcon,
                        mobile: PhoneAndroidIcon,
                        printer: PrintIcon,
                        tv: TvIcon,
                        speaker: SpeakerIcon,
                        gamepad: DevicesIcon,
                        vr_headset: ViewInArIcon,
                        // Hardware
                        cpu: MemoryIcon,
                        memory: DeveloperBoardIcon,
                        usb: UsbIcon,
                        bluetooth: BluetoothIcon,
                        keyboard: KeyboardIcon,
                        mouse: MouseOutlinedIcon,
                        ssd: StorageIcon,
                        gpu: DeveloperBoardIcon,
                        rack: StorageIcon,
                        nas: StorageIcon,
                        // Cloud
                        cloud: CloudIcon,
                        internet: PublicIcon,
                        aws: CloudQueueIcon,
                        azure: CloudQueueIcon,
                        gcp: CloudQueueIcon,
                        alibaba: CloudQueueIcon,
                        huawei: CloudQueueIcon,
                        yandex: CloudQueueIcon,
                        oracle: CloudQueueIcon,
                        ibm: CloudQueueIcon,
                        digitalocean: CloudQueueIcon,
                        // AI/LLM
                        openai: SmartToyIcon,
                        anthropic: PsychologyIcon,
                        google_ai: AutoAwesomeIcon,
                        meta_ai: SmartToyIcon,
                        deepseek: PsychologyIcon,
                        qwen: SmartToyIcon,
                        mistral: AutoAwesomeIcon,
                        xai: SmartToyIcon,
                        kimi: PsychologyIcon,
                        zhipu: SmartToyIcon,
                        cohere: PsychologyIcon,
                        huggingface: AutoAwesomeIcon,
                        ollama: SmartToyIcon,
                        llm_generic: PsychologyIcon,
                      }[symbol.id] || DevicesIcon;
                      
                      return (
                        <Tooltip key={symbol.id} title={symbol.name}>
                          <IconButton
                            onClick={() => {
                              setSelectedSymbol(symbol.id);
                              setSelectedTool('symbol');
                              setSymbolsAnchor(null);
                            }}
                            size="small"
                            sx={{
                              border: selectedSymbol === symbol.id && selectedTool === 'symbol' 
                                ? '2px solid #3b82f6' 
                                : '1px solid rgba(255,255,255,0.1)',
                              bgcolor: selectedSymbol === symbol.id && selectedTool === 'symbol'
                                ? alpha('#3b82f6', 0.2)
                                : 'transparent',
                              '&:hover': {
                                bgcolor: alpha('#3b82f6', 0.1),
                              }
                            }}
                          >
                            <IconComponent sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                      );
                    })}
                  </Box>
                </Box>
              );
            })}

            {/* Selected symbol indicator */}
            {selectedTool === 'symbol' && selectedSymbol && (
              <Box sx={{ 
                mt: 1, 
                p: 1, 
                bgcolor: alpha('#3b82f6', 0.1), 
                borderRadius: 1,
                display: 'flex',
                alignItems: 'center',
                gap: 1
              }}>
                <Typography variant="caption" sx={{ color: 'primary.main' }}>
                  Selected: {NETWORK_SYMBOLS.find(s => s.id === selectedSymbol)?.name}
                </Typography>
              </Box>
            )}
          </Box>
        </Popover>

        <Divider orientation="vertical" flexItem />

        {/* Color pickers */}
        <Tooltip title="Stroke Color">
          <IconButton
            onClick={(e) => { setColorAnchor(e.currentTarget); setColorType('stroke'); }}
            sx={{ border: `2px solid ${strokeColor}`, width: 32, height: 32 }}
          />
        </Tooltip>

        <Tooltip title="Fill Color">
          <IconButton
            onClick={(e) => { setColorAnchor(e.currentTarget); setColorType('fill'); }}
            sx={{
              bgcolor: fillColor || 'transparent',
              border: `2px solid ${fillColor || alpha('#ffffff', 0.3)}`,
              width: 32,
              height: 32,
            }}
          />
        </Tooltip>

        <Popover
          open={Boolean(colorAnchor)}
          anchorEl={colorAnchor}
          onClose={() => setColorAnchor(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
        >
          <Box sx={{ p: 2, display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0.5 }}>
            {colorType === 'fill' && (
              <IconButton
                onClick={() => { setFillColor(null); setColorAnchor(null); }}
                sx={{ border: `1px solid ${alpha('#ffffff', 0.3)}` }}
              >
                <Typography variant="caption">∅</Typography>
              </IconButton>
            )}
            {COLORS.map(color => (
              <IconButton
                key={color}
                onClick={() => {
                  if (colorType === 'stroke') setStrokeColor(color);
                  else setFillColor(color);
                  setColorAnchor(null);
                }}
                sx={{ bgcolor: color, width: 28, height: 28, border: '1px solid rgba(255,255,255,0.2)' }}
              />
            ))}
          </Box>
        </Popover>

        {/* Stroke width */}
        <Tooltip title="Stroke Width">
          <Box sx={{ width: 80, ml: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', minWidth: 20 }}>{strokeWidth}</Typography>
            <Slider
              value={strokeWidth}
              onChange={(_, v) => setStrokeWidth(v as number)}
              min={1}
              max={20}
              size="small"
            />
          </Box>
        </Tooltip>

        {/* Font size */}
        <Tooltip title="Font Size">
          <Box sx={{ width: 80, ml: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <FormatSizeIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            <Slider
              value={fontSize}
              onChange={(_, v) => setFontSize(v as number)}
              min={10}
              max={72}
              size="small"
            />
          </Box>
        </Tooltip>

        <Divider orientation="vertical" flexItem />

        {/* Grid toggle */}
        <Tooltip title={`Grid ${showGrid ? 'On' : 'Off'} (G)`}>
          <IconButton onClick={() => setShowGrid(prev => !prev)} color={showGrid ? 'primary' : 'default'}>
            {showGrid ? <GridOnIcon sx={{ fontSize: 18 }} /> : <GridOffIcon sx={{ fontSize: 18 }} />}
          </IconButton>
        </Tooltip>

        {/* Copy/Paste */}
        <Tooltip title="Copy (Ctrl+C)">
          <span>
            <IconButton onClick={copySelected} disabled={!selectedElement}>
              <ContentCopyIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title="Paste (Ctrl+V)">
          <span>
            <IconButton onClick={pasteElement} disabled={!clipboard}>
              <ContentPasteIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </span>
        </Tooltip>

        {/* Image upload */}
        <input
          type="file"
          accept="image/*"
          ref={imageInputRef}
          style={{ display: 'none' }}
          onChange={handleImageUpload}
        />
        <Tooltip title="Add Image">
          <IconButton onClick={() => imageInputRef.current?.click()}>
            <AddPhotoAlternateIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>

        <Divider orientation="vertical" flexItem />

        {/* Layer ordering */}
        <Tooltip title="Bring to Front">
          <span>
            <IconButton onClick={bringToFront} disabled={!selectedElement}>
              <FlipToFrontIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title="Send to Back">
          <span>
            <IconButton onClick={sendToBack} disabled={!selectedElement}>
              <FlipToBackIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </span>
        </Tooltip>

        {/* Opacity control */}
        {selectedElement && (
          <Tooltip title="Opacity">
            <Box sx={{ width: 80, ml: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <OpacityIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
              <Slider
                value={selectedElement.opacity || 1}
                onChange={(_, v) => updateElementOpacity(v as number)}
                min={0.1}
                max={1}
                step={0.1}
                size="small"
              />
            </Box>
          </Tooltip>
        )}

        <Divider orientation="vertical" flexItem />

        {/* Undo/Redo */}
        <IconButton onClick={undo} disabled={historyIndex <= 0}>
          <UndoIcon sx={{ fontSize: 18 }} />
        </IconButton>
        <IconButton onClick={redo} disabled={historyIndex >= history.length - 1}>
          <RedoIcon sx={{ fontSize: 18 }} />
        </IconButton>

        {/* Delete */}
        <IconButton onClick={deleteSelected} disabled={!selectedElement} color="error">
          <DeleteIcon sx={{ fontSize: 18 }} />
        </IconButton>

        <Divider orientation="vertical" flexItem />

        {/* Zoom controls */}
        <IconButton onClick={() => setZoom(prev => Math.min(prev * 1.2, 5))}>
          <ZoomInIcon sx={{ fontSize: 18 }} />
        </IconButton>
        <Typography variant="body2" sx={{ minWidth: 50, textAlign: 'center' }}>
          {Math.round(zoom * 100)}%
        </Typography>
        <IconButton onClick={() => setZoom(prev => Math.max(prev / 1.2, 0.1))}>
          <ZoomOutIcon sx={{ fontSize: 18 }} />
        </IconButton>
        <Tooltip title="Reset View (Home)">
          <IconButton onClick={resetView}>
            <CenterFocusStrongIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>

        <Divider orientation="vertical" flexItem />

        {/* Export */}
        <Tooltip title="Export as Image">
          <IconButton onClick={() => setExportDialogOpen(true)}>
            <DownloadIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>

        {/* Clear All */}
        <Tooltip title="Clear All Elements">
          <span>
            <IconButton 
              onClick={() => setClearAllDialogOpen(true)} 
              disabled={elements.length === 0}
              sx={{ color: elements.length > 0 ? '#ef4444' : undefined }}
            >
              <DeleteIcon sx={{ fontSize: 18 }} />
            </IconButton>
          </span>
        </Tooltip>

        {/* Select All / Duplicate */}
        <Tooltip title="Select All (Ctrl+A)">
          <IconButton onClick={selectAll}>
            <SelectAllIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
        <Tooltip title="Duplicate (Ctrl+D)">
          <span>
            <IconButton onClick={duplicateElement} disabled={!selectedElement}>
              <ContentCutIcon sx={{ fontSize: 18, transform: 'rotate(45deg)' }} />
            </IconButton>
          </span>
        </Tooltip>

        {/* Lock/Unlock */}
        <Tooltip title={selectedElement && lockedElements.has(selectedElement.element_id) ? "Unlock (Ctrl+L)" : "Lock (Ctrl+L)"}>
          <span>
            <IconButton onClick={toggleLock} disabled={!selectedElement}>
              {selectedElement && lockedElements.has(selectedElement.element_id) 
                ? <LockIcon sx={{ fontSize: 18 }} /> 
                : <LockOpenIcon sx={{ fontSize: 18 }} />}
            </IconButton>
          </span>
        </Tooltip>

        {/* Snap to Grid toggle */}
        <Tooltip title={`Snap to Grid ${snapToGrid ? 'On' : 'Off'} (Shift+G)`}>
          <IconButton onClick={() => setSnapToGrid(prev => !prev)} color={snapToGrid ? 'primary' : 'default'}>
            <GridOnIcon sx={{ fontSize: 18, opacity: snapToGrid ? 1 : 0.5 }} />
          </IconButton>
        </Tooltip>

        {/* Zoom to Fit */}
        <Tooltip title="Zoom to Fit (F)">
          <IconButton onClick={zoomToFit}>
            <FitScreenIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>

        {/* Fullscreen Toggle */}
        <Tooltip title={isFullscreen ? "Exit Fullscreen (F11)" : "Fullscreen (F11)"}>
          <IconButton onClick={toggleFullscreen}>
            {isFullscreen ? (
              <FullscreenExitIcon sx={{ fontSize: 18 }} />
            ) : (
              <FullscreenIcon sx={{ fontSize: 18 }} />
            )}
          </IconButton>
        </Tooltip>

        <Divider orientation="vertical" flexItem />

        {/* Alignment buttons - only show when multiple selected */}
        {multiSelection.length >= 2 && (
          <>
            <Tooltip title="Align Left">
              <IconButton onClick={() => alignElements('left')} size="small">
                <AlignHorizontalLeftIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Align Center">
              <IconButton onClick={() => alignElements('center')} size="small">
                <AlignHorizontalCenterIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Align Right">
              <IconButton onClick={() => alignElements('right')} size="small">
                <AlignHorizontalRightIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Align Top">
              <IconButton onClick={() => alignElements('top')} size="small">
                <VerticalAlignTopIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Align Middle">
              <IconButton onClick={() => alignElements('middle')} size="small">
                <VerticalAlignCenterIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
            <Tooltip title="Align Bottom">
              <IconButton onClick={() => alignElements('bottom')} size="small">
                <VerticalAlignBottomIcon sx={{ fontSize: 16 }} />
              </IconButton>
            </Tooltip>
            <Divider orientation="vertical" flexItem />
          </>
        )}

        <Box sx={{ flexGrow: 1 }} />

        {/* Active users */}
        {remoteUsers.length > 0 && (
          <AvatarGroup max={5} sx={{ mr: 2 }}>
            {remoteUsers.map(user => (
              <Tooltip key={user.user_id} title={user.username}>
                <Avatar sx={{ bgcolor: user.color, width: 28, height: 28, fontSize: 12 }}>
                  {user.username[0].toUpperCase()}
                </Avatar>
              </Tooltip>
            ))}
          </AvatarGroup>
        )}

        <Chip
          icon={<GroupIcon sx={{ fontSize: 14 }} />}
          label={`${remoteUsers.length + 1} online`}
          size="small"
          variant="outlined"
        />
      </Paper>

      {/* Canvas */}
      <Box
        ref={containerRef}
        sx={{ flex: 1, overflow: 'hidden', cursor: selectedTool === 'pan' ? 'grab' : 'crosshair', position: 'relative' }}
      >
        <canvas
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onDoubleClick={handleDoubleClick}
          onContextMenu={handleContextMenu}
          onWheel={handleWheel}
          style={{ display: 'block', width: '100%', height: '100%' }}
        />
        
        {/* Text editing overlay - using ref to prevent flickering */}
        {editingTextId && editingElementRef.current && (() => {
          const elRef = editingElementRef.current;
          const isSticky = elRef.element_type === 'sticky';
          const isText = elRef.element_type === 'text';
          return (
            <Box
              data-text-editor-container="true"
              onClick={(e) => e.stopPropagation()}
              onMouseDown={(e) => e.stopPropagation()}
              onMouseUp={(e) => e.stopPropagation()}
              onMouseMove={(e) => e.stopPropagation()}
              sx={{
                position: 'absolute',
                left: elRef.x * zoom + panOffset.x - 2,
                top: elRef.y * zoom + panOffset.y - 2,
                width: Math.max((elRef.width * zoom) + 4, 200),
                minHeight: isSticky ? (elRef.height * zoom) + 4 : 'auto',
                zIndex: 2000,
                pointerEvents: 'auto',
              }}
            >
              <TextField
                ref={textInputRef}
                value={editingText}
                onChange={(e) => setEditingText(e.target.value)}
                onFocus={(e) => e.stopPropagation()}
                onBlur={(e) => {
                  // Don't save on blur - only save on button click or Ctrl+Enter
                  // This prevents accidental saves and flickering
                }}
                onMouseDown={(e) => e.stopPropagation()}
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => {
                  e.stopPropagation();
                  if (e.key === 'Escape') {
                    e.preventDefault();
                    editingElementRef.current = null;
                    setEditingTextId(null);
                    setEditingText('');
                  }
                  // Ctrl+Enter or Cmd+Enter to save
                  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    saveTextEdit();
                  }
                }}
                multiline
                minRows={isText ? 2 : (isSticky ? 3 : 2)}
                maxRows={20}
                variant="outlined"
                size="small"
                autoFocus
                data-text-editor="true"
                placeholder={isSticky ? "Type your note here..." : "Enter text... (Ctrl+Enter to save)"}
                sx={{
                  width: '100%',
                  '& .MuiOutlinedInput-root': {
                    bgcolor: isSticky ? (elRef.fill_color || '#fef08a') : 'rgba(30, 30, 46, 0.98)',
                    color: isSticky ? '#1e1e2e' : (elRef.stroke_color || '#ffffff'),
                    fontSize: `${(elRef.font_size || 16) * zoom}px`,
                    fontFamily: isSticky ? '"Patrick Hand", cursive, sans-serif' : 'inherit',
                    lineHeight: 1.6,
                    padding: '8px 12px',
                    minHeight: isSticky ? elRef.height * zoom : 60,
                    alignItems: 'flex-start',
                    '& textarea': {
                      cursor: 'text',
                      resize: 'none',
                      '&::selection': {
                        backgroundColor: isSticky ? 'rgba(0,0,0,0.2)' : 'rgba(59, 130, 246, 0.4)',
                      },
                    },
                  },
                  '& .MuiOutlinedInput-notchedOutline': {
                    borderColor: '#3b82f6',
                    borderWidth: 2,
                  },
                  '&:hover .MuiOutlinedInput-notchedOutline': {
                    borderColor: '#60a5fa',
                  },
                  '& .MuiOutlinedInput-root.Mui-focused .MuiOutlinedInput-notchedOutline': {
                    borderColor: '#3b82f6',
                    borderWidth: 2,
                    boxShadow: '0 0 0 3px rgba(59, 130, 246, 0.3)',
                  },
                }}
              />
              {/* Save/Cancel buttons */}
              <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 0.5, gap: 0.5 }}>
                <Button
                  size="small"
                  variant="contained"
                  color="primary"
                  onMouseDown={(e) => e.stopPropagation()}
                  onClick={(e) => {
                    e.stopPropagation();
                    saveTextEdit();
                  }}
                  sx={{ 
                    minWidth: 60, 
                    fontSize: '0.75rem',
                    py: 0.25,
                    textTransform: 'none',
                  }}
                >
                  Save
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  onMouseDown={(e) => e.stopPropagation()}
                  onClick={(e) => {
                    e.stopPropagation();
                    editingElementRef.current = null;
                    setEditingTextId(null);
                    setEditingText('');
                  }}
                  sx={{ 
                    minWidth: 60, 
                    fontSize: '0.75rem',
                    py: 0.25,
                    textTransform: 'none',
                    borderColor: 'rgba(255,255,255,0.3)',
                    color: 'rgba(255,255,255,0.7)',
                    '&:hover': {
                      borderColor: 'rgba(255,255,255,0.5)',
                      bgcolor: 'rgba(255,255,255,0.1)',
                    }
                  }}
                >
                  Cancel
                </Button>
              </Box>
            </Box>
          );
        })()}
        
        {/* Table cell editing overlay */}
        {editingTableCell && (() => {
          const el = elements.find(e => e.element_id === editingTableCell.elementId);
          if (!el || el.element_type !== 'table') return null;
          
          const rows = el.table_rows || 3;
          const cols = el.table_cols || 3;
          const cellWidth = el.width / cols;
          const cellHeight = el.height / rows;
          const cellX = el.x + editingTableCell.col * cellWidth;
          const cellY = el.y + editingTableCell.row * cellHeight;
          
          return (
            <TextField
              ref={tableCellInputRef}
              value={tableCellText}
              onChange={(e) => setTableCellText(e.target.value)}
              onBlur={saveTableCellEdit}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  saveTableCellEdit();
                }
                if (e.key === 'Escape') {
                  setEditingTableCell(null);
                  setTableCellText('');
                }
                if (e.key === 'Tab') {
                  e.preventDefault();
                  saveTableCellEdit();
                  // Move to next cell
                  const nextCol = editingTableCell.col + 1;
                  const nextRow = editingTableCell.row;
                  if (nextCol < cols) {
                    startEditingTableCell(el, nextRow, nextCol);
                  } else if (nextRow + 1 < rows) {
                    startEditingTableCell(el, nextRow + 1, 0);
                  }
                }
              }}
              variant="outlined"
              size="small"
              autoFocus
              sx={{
                position: 'absolute',
                left: cellX * zoom + panOffset.x,
                top: cellY * zoom + panOffset.y,
                width: cellWidth * zoom,
                height: cellHeight * zoom,
                '& .MuiOutlinedInput-root': {
                  bgcolor: '#2d3748',
                  color: '#ffffff',
                  fontSize: `${(el.font_size || 12) * zoom}px`,
                  height: '100%',
                  '& input': {
                    textAlign: 'center',
                    padding: '4px',
                  }
                },
                '& .MuiOutlinedInput-notchedOutline': {
                  borderColor: '#3b82f6',
                  borderWidth: 2,
                }
              }}
            />
          );
        })()}
        
        {/* Multi-selection count badge */}
        {multiSelection.length > 0 && (
          <Chip
            label={`${multiSelection.length} selected`}
            size="small"
            color="primary"
            sx={{ position: 'absolute', top: 8, left: 8 }}
            onDelete={clearSelection}
          />
        )}

        {/* Fullscreen close button */}
        {isFullscreen && (
          <IconButton
            onClick={toggleFullscreen}
            sx={{
              position: 'absolute',
              top: 12,
              right: 12,
              bgcolor: 'error.main',
              color: 'white',
              width: 32,
              height: 32,
              '&:hover': {
                bgcolor: 'error.dark',
                transform: 'scale(1.1)',
              },
              boxShadow: 3,
              transition: 'all 0.2s ease',
              zIndex: 1000,
            }}
          >
            <CloseIcon sx={{ fontSize: 20 }} />
          </IconButton>
        )}
      </Box>

      {/* Right-click context menu */}
      <Menu
        open={contextMenu !== null}
        onClose={handleContextMenuClose}
        anchorReference="anchorPosition"
        anchorPosition={
          contextMenu !== null
            ? { top: contextMenu.y, left: contextMenu.x }
            : undefined
        }
      >
        {contextMenu?.element ? (
          <>
            <MenuItem onClick={handleContextMenuDelete}>
              <ListItemIcon>
                <DeleteIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Delete</ListItemText>
            </MenuItem>
            <MenuItem onClick={handleContextMenuDuplicate}>
              <ListItemIcon>
                <ContentCopyIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Duplicate</ListItemText>
            </MenuItem>
            <Divider />
            
            {/* Voting Section */}
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
              Vote (Dot Voting)
            </Typography>
            <Box sx={{ display: 'flex', gap: 0.5, px: 2, py: 1 }}>
              {VOTE_COLORS.map(color => (
                <IconButton
                  key={color}
                  size="small"
                  onClick={() => handleAddVote(color)}
                  sx={{ 
                    bgcolor: color, 
                    width: 24, 
                    height: 24,
                    '&:hover': { bgcolor: color, opacity: 0.8 }
                  }}
                />
              ))}
            </Box>
            <MenuItem onClick={handleRemoveVote}>
              <ListItemText sx={{ pl: 1 }}>Remove My Vote</ListItemText>
            </MenuItem>
            <Divider />
            
            {/* Status Section */}
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
              Status
            </Typography>
            <MenuItem onClick={() => handleSetStatus('on_track')}>
              <ListItemIcon>
                <CheckCircleIcon fontSize="small" sx={{ color: '#22c55e' }} />
              </ListItemIcon>
              <ListItemText>On Track</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetStatus('at_risk')}>
              <ListItemIcon>
                <WarningIcon fontSize="small" sx={{ color: '#f59e0b' }} />
              </ListItemIcon>
              <ListItemText>At Risk</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetStatus('blocked')}>
              <ListItemIcon>
                <BlockIcon fontSize="small" sx={{ color: '#ef4444' }} />
              </ListItemIcon>
              <ListItemText>Blocked</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetStatus('done')}>
              <ListItemIcon>
                <CheckCircleIcon fontSize="small" sx={{ color: '#3b82f6' }} />
              </ListItemIcon>
              <ListItemText>Done</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetStatus('none')}>
              <ListItemText sx={{ pl: 4 }}>Clear Status</ListItemText>
            </MenuItem>
            <Divider />
            
            {/* Priority Section */}
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
              Priority
            </Typography>
            <MenuItem onClick={() => handleSetPriority('p1')}>
              <ListItemIcon>
                <FlagIcon fontSize="small" sx={{ color: '#ef4444' }} />
              </ListItemIcon>
              <ListItemText>P1 - High</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetPriority('p2')}>
              <ListItemIcon>
                <FlagIcon fontSize="small" sx={{ color: '#f59e0b' }} />
              </ListItemIcon>
              <ListItemText>P2 - Medium</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetPriority('p3')}>
              <ListItemIcon>
                <FlagIcon fontSize="small" sx={{ color: '#3b82f6' }} />
              </ListItemIcon>
              <ListItemText>P3 - Low</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleSetPriority('none')}>
              <ListItemText sx={{ pl: 4 }}>Clear Priority</ListItemText>
            </MenuItem>
            <Divider />
            
            <MenuItem onClick={() => { bringToFront(); handleContextMenuClose(); }}>
              <ListItemText>Bring to Front</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => { sendToBack(); handleContextMenuClose(); }}>
              <ListItemText>Send to Back</ListItemText>
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => { toggleLock(); handleContextMenuClose(); }}>
              <ListItemIcon>
                {lockedElements.has(contextMenu.element.element_id) ? <LockOpenIcon fontSize="small" /> : <LockIcon fontSize="small" />}
              </ListItemIcon>
              <ListItemText>{lockedElements.has(contextMenu.element.element_id) ? 'Unlock' : 'Lock'}</ListItemText>
            </MenuItem>
            <Divider />
            
            {/* Group/Ungroup Section */}
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
              Grouping
            </Typography>
            {multiSelection.length >= 2 && (
              <MenuItem onClick={() => { groupSelectedElements(); handleContextMenuClose(); }}>
                <ListItemIcon>
                  <GroupWorkIcon fontSize="small" sx={{ color: '#8b5cf6' }} />
                </ListItemIcon>
                <ListItemText>Group Selected ({multiSelection.length})</ListItemText>
              </MenuItem>
            )}
            {contextMenu.element?.group_id && (
              <>
                <MenuItem onClick={() => { selectGroup(contextMenu.element!.group_id!); handleContextMenuClose(); }}>
                  <ListItemIcon>
                    <GroupsIcon fontSize="small" sx={{ color: '#3b82f6' }} />
                  </ListItemIcon>
                  <ListItemText>Select Group</ListItemText>
                </MenuItem>
                <MenuItem onClick={() => { ungroupSelectedElements(); handleContextMenuClose(); }}>
                  <ListItemIcon>
                    <LinkOffIcon fontSize="small" sx={{ color: '#f97316' }} />
                  </ListItemIcon>
                  <ListItemText>Ungroup</ListItemText>
                </MenuItem>
              </>
            )}
            <Divider />
            
            {/* Comments Section */}
            <MenuItem onClick={() => { 
              setCommentingElement(contextMenu.element); 
              setCommentsPanelOpen(true); 
              handleContextMenuClose(); 
            }}>
              <ListItemIcon>
                <CommentIcon fontSize="small" sx={{ color: '#3b82f6' }} />
              </ListItemIcon>
              <ListItemText>
                Comments {contextMenu.element?.comments?.length ? `(${contextMenu.element.comments.length})` : ''}
              </ListItemText>
            </MenuItem>
            
            {/* Link Element - Open Link */}
            {contextMenu.element?.element_type === 'link' && contextMenu.element?.link_url && (
              <MenuItem onClick={() => { openLinkInNewTab(contextMenu.element!); handleContextMenuClose(); }}>
                <ListItemIcon>
                  <LaunchIcon fontSize="small" sx={{ color: '#22c55e' }} />
                </ListItemIcon>
                <ListItemText>Open Link</ListItemText>
              </MenuItem>
            )}
            
            {/* Sticky Note Size */}
            {contextMenu.element?.element_type === 'sticky' && (
              <>
                <Divider />
                <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
                  Sticky Size
                </Typography>
                <MenuItem onClick={() => { changeStickySize('small'); handleContextMenuClose(); }}>
                  <ListItemIcon>
                    <PhotoSizeSelectSmallIcon fontSize="small" />
                  </ListItemIcon>
                  <ListItemText>Small</ListItemText>
                </MenuItem>
                <MenuItem onClick={() => { changeStickySize('medium'); handleContextMenuClose(); }}>
                  <ListItemIcon>
                    <AspectRatioIcon fontSize="small" />
                  </ListItemIcon>
                  <ListItemText>Medium</ListItemText>
                </MenuItem>
                <MenuItem onClick={() => { changeStickySize('large'); handleContextMenuClose(); }}>
                  <ListItemIcon>
                    <PhotoSizeSelectLargeIcon fontSize="small" />
                  </ListItemIcon>
                  <ListItemText>Large</ListItemText>
                </MenuItem>
              </>
            )}
            
            {/* Table Row/Column Options */}
            {contextMenu.element?.element_type === 'table' && (
              <>
                <Divider />
                <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
                  Table Rows
                </Typography>
                <MenuItem onClick={() => addTableRow('above')}>
                  <ListItemIcon>
                    <VerticalAlignTopIcon fontSize="small" sx={{ color: '#3b82f6' }} />
                  </ListItemIcon>
                  <ListItemText>Insert Row Above</ListItemText>
                </MenuItem>
                <MenuItem onClick={() => addTableRow('below')}>
                  <ListItemIcon>
                    <VerticalAlignBottomIcon fontSize="small" sx={{ color: '#3b82f6' }} />
                  </ListItemIcon>
                  <ListItemText>Insert Row Below</ListItemText>
                </MenuItem>
                <MenuItem onClick={deleteTableRow}>
                  <ListItemIcon>
                    <DeleteIcon fontSize="small" sx={{ color: '#ef4444' }} />
                  </ListItemIcon>
                  <ListItemText>Delete Row</ListItemText>
                </MenuItem>
                <Divider />
                <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
                  Table Columns
                </Typography>
                <MenuItem onClick={() => addTableColumn('left')}>
                  <ListItemIcon>
                    <AlignHorizontalLeftIcon fontSize="small" sx={{ color: '#22c55e' }} />
                  </ListItemIcon>
                  <ListItemText>Insert Column Left</ListItemText>
                </MenuItem>
                <MenuItem onClick={() => addTableColumn('right')}>
                  <ListItemIcon>
                    <AlignHorizontalRightIcon fontSize="small" sx={{ color: '#22c55e' }} />
                  </ListItemIcon>
                  <ListItemText>Insert Column Right</ListItemText>
                </MenuItem>
                <MenuItem onClick={deleteTableColumn}>
                  <ListItemIcon>
                    <DeleteIcon fontSize="small" sx={{ color: '#ef4444' }} />
                  </ListItemIcon>
                  <ListItemText>Delete Column</ListItemText>
                </MenuItem>
              </>
            )}
            
            {/* Timer Controls */}
            {contextMenu.element?.element_type === 'timer' && (
              <>
                <Divider />
                <Typography variant="caption" sx={{ px: 2, py: 0.5, color: 'text.secondary', display: 'block' }}>
                  Timer Controls
                </Typography>
                {(!contextMenu.element.timer_started_at || contextMenu.element.timer_paused_at) ? (
                  <MenuItem onClick={startTimer}>
                    <ListItemIcon>
                      <PlayArrowIcon fontSize="small" sx={{ color: '#22c55e' }} />
                    </ListItemIcon>
                    <ListItemText>{contextMenu.element.timer_paused_at ? 'Resume' : 'Start'}</ListItemText>
                  </MenuItem>
                ) : (
                  <MenuItem onClick={pauseTimer}>
                    <ListItemIcon>
                      <PauseIcon fontSize="small" sx={{ color: '#f59e0b' }} />
                    </ListItemIcon>
                    <ListItemText>Pause</ListItemText>
                  </MenuItem>
                )}
                <MenuItem onClick={resetTimer}>
                  <ListItemIcon>
                    <ReplayIcon fontSize="small" sx={{ color: '#3b82f6' }} />
                  </ListItemIcon>
                  <ListItemText>Reset</ListItemText>
                </MenuItem>
                <MenuItem onClick={setTimerDuration}>
                  <ListItemIcon>
                    <TimerIcon fontSize="small" sx={{ color: '#8b5cf6' }} />
                  </ListItemIcon>
                  <ListItemText>Set Duration</ListItemText>
                </MenuItem>
              </>
            )}
          </>
        ) : (
          <MenuItem disabled>
            <ListItemText>Right-click on an element</ListItemText>
          </MenuItem>
        )}
      </Menu>

      {/* Export Format Dialog */}
      <Dialog open={exportDialogOpen} onClose={() => setExportDialogOpen(false)}>
        <DialogTitle>Export Whiteboard</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2, color: 'text.secondary' }}>
            Choose the export format for your whiteboard:
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
            <Button
              variant="contained"
              onClick={() => exportCanvas('png')}
              sx={{ 
                minWidth: 120,
                flexDirection: 'column',
                py: 2,
                bgcolor: '#3b82f6',
                '&:hover': { bgcolor: '#2563eb' }
              }}
            >
              <ImageIcon sx={{ fontSize: 32, mb: 1 }} />
              <Typography variant="subtitle2">PNG</Typography>
              <Typography variant="caption" sx={{ opacity: 0.7 }}>Lossless, transparent</Typography>
            </Button>
            <Button
              variant="contained"
              onClick={() => exportCanvas('jpeg')}
              sx={{ 
                minWidth: 120,
                flexDirection: 'column',
                py: 2,
                bgcolor: '#22c55e',
                '&:hover': { bgcolor: '#16a34a' }
              }}
            >
              <ImageIcon sx={{ fontSize: 32, mb: 1 }} />
              <Typography variant="subtitle2">JPG</Typography>
              <Typography variant="caption" sx={{ opacity: 0.7 }}>Smaller file size</Typography>
            </Button>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExportDialogOpen(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>

      {/* Templates Dialog */}
      <Dialog 
        open={templatesDialogOpen} 
        onClose={() => setTemplatesDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <DashboardCustomizeIcon sx={{ color: '#8b5cf6' }} /> Templates Library
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 3, color: 'text.secondary' }}>
            Select a template to add pre-configured elements to your whiteboard. Templates are added to the current canvas.
          </Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 2 }}>
            {/* Retrospective Template */}
            <Paper
              onClick={() => applyTemplate('retrospective')}
              sx={{
                p: 2,
                cursor: 'pointer',
                border: '2px solid transparent',
                transition: 'all 0.2s',
                '&:hover': { 
                  border: '2px solid #22c55e',
                  bgcolor: alpha('#22c55e', 0.05),
                  transform: 'translateY(-2px)'
                }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Box sx={{ 
                  width: 40, height: 40, borderRadius: 1, 
                  bgcolor: '#22c55e20', display: 'flex', 
                  alignItems: 'center', justifyContent: 'center' 
                }}>
                  🔄
                </Box>
                <Typography variant="subtitle1" fontWeight={600}>Sprint Retrospective</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Three-column layout: What went well, What didn't, Action items. Perfect for agile team retrospectives.
              </Typography>
              <Box sx={{ display: 'flex', gap: 0.5, mt: 1 }}>
                <Chip label="Agile" size="small" sx={{ bgcolor: '#22c55e20', color: '#22c55e', fontSize: '0.7rem' }} />
                <Chip label="Scrum" size="small" sx={{ bgcolor: '#3b82f620', color: '#3b82f6', fontSize: '0.7rem' }} />
              </Box>
            </Paper>

            {/* SWOT Template */}
            <Paper
              onClick={() => applyTemplate('swot')}
              sx={{
                p: 2,
                cursor: 'pointer',
                border: '2px solid transparent',
                transition: 'all 0.2s',
                '&:hover': { 
                  border: '2px solid #3b82f6',
                  bgcolor: alpha('#3b82f6', 0.05),
                  transform: 'translateY(-2px)'
                }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Box sx={{ 
                  width: 40, height: 40, borderRadius: 1, 
                  bgcolor: '#3b82f620', display: 'flex', 
                  alignItems: 'center', justifyContent: 'center' 
                }}>
                  📊
                </Box>
                <Typography variant="subtitle1" fontWeight={600}>SWOT Analysis</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Four-quadrant analysis: Strengths, Weaknesses, Opportunities, Threats. Strategic planning essential.
              </Typography>
              <Box sx={{ display: 'flex', gap: 0.5, mt: 1 }}>
                <Chip label="Strategy" size="small" sx={{ bgcolor: '#3b82f620', color: '#3b82f6', fontSize: '0.7rem' }} />
                <Chip label="Planning" size="small" sx={{ bgcolor: '#8b5cf620', color: '#8b5cf6', fontSize: '0.7rem' }} />
              </Box>
            </Paper>

            {/* Mind Map Template */}
            <Paper
              onClick={() => applyTemplate('mindmap')}
              sx={{
                p: 2,
                cursor: 'pointer',
                border: '2px solid transparent',
                transition: 'all 0.2s',
                '&:hover': { 
                  border: '2px solid #8b5cf6',
                  bgcolor: alpha('#8b5cf6', 0.05),
                  transform: 'translateY(-2px)'
                }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Box sx={{ 
                  width: 40, height: 40, borderRadius: 1, 
                  bgcolor: '#8b5cf620', display: 'flex', 
                  alignItems: 'center', justifyContent: 'center' 
                }}>
                  🧠
                </Box>
                <Typography variant="subtitle1" fontWeight={600}>Mind Map</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Central idea with 6 branches and sub-branches. Great for brainstorming and idea exploration.
              </Typography>
              <Box sx={{ display: 'flex', gap: 0.5, mt: 1 }}>
                <Chip label="Brainstorm" size="small" sx={{ bgcolor: '#8b5cf620', color: '#8b5cf6', fontSize: '0.7rem' }} />
                <Chip label="Creative" size="small" sx={{ bgcolor: '#ec489920', color: '#ec4899', fontSize: '0.7rem' }} />
              </Box>
            </Paper>

            {/* Risk Matrix Template */}
            <Paper
              onClick={() => applyTemplate('riskmatrix')}
              sx={{
                p: 2,
                cursor: 'pointer',
                border: '2px solid transparent',
                transition: 'all 0.2s',
                '&:hover': { 
                  border: '2px solid #ef4444',
                  bgcolor: alpha('#ef4444', 0.05),
                  transform: 'translateY(-2px)'
                }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Box sx={{ 
                  width: 40, height: 40, borderRadius: 1, 
                  bgcolor: '#ef444420', display: 'flex', 
                  alignItems: 'center', justifyContent: 'center' 
                }}>
                  ⚠️
                </Box>
                <Typography variant="subtitle1" fontWeight={600}>Risk Matrix</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                5x5 Impact vs Probability grid with color-coded risk levels. Essential for PRINCE2 and risk management.
              </Typography>
              <Box sx={{ display: 'flex', gap: 0.5, mt: 1 }}>
                <Chip label="PRINCE2" size="small" sx={{ bgcolor: '#ef444420', color: '#ef4444', fontSize: '0.7rem' }} />
                <Chip label="Risk Mgmt" size="small" sx={{ bgcolor: '#f9731620', color: '#f97316', fontSize: '0.7rem' }} />
              </Box>
            </Paper>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTemplatesDialogOpen(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>

      {/* Clear All Confirmation Dialog */}
      <Dialog open={clearAllDialogOpen} onClose={() => setClearAllDialogOpen(false)}>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, color: '#ef4444' }}>
          <DeleteIcon /> Clear All Elements?
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" sx={{ mb: 1 }}>
            Are you sure you want to delete <strong>all {elements.length} element{elements.length !== 1 ? 's' : ''}</strong> from this whiteboard?
          </Typography>
          <Typography variant="body2" sx={{ color: 'warning.main' }}>
            ⚠️ This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setClearAllDialogOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            color="error" 
            onClick={async () => {
              // Delete all elements from database
              try {
                for (const el of elements) {
                  await whiteboardClient.deleteElement(Number(whiteboardId), el.element_id);
                  sendWsMessage({ type: 'delete', elementId: el.element_id });
                }
              } catch (error) {
                console.error('Failed to delete elements:', error);
              }
              
              // Clear local state
              setElements([]);
              setSelectedElement(null);
              setMultiSelection([]);
              setLockedElements(new Set());
              setHistory([[]]);
              setHistoryIndex(0);
              
              setClearAllDialogOpen(false);
              setSnackbar({ open: true, message: 'All elements cleared!', severity: 'success' });
            }}
          >
            Clear All
          </Button>
        </DialogActions>
      </Dialog>

      {/* Search Dialog */}
      <Dialog
        open={searchOpen}
        onClose={() => { setSearchOpen(false); setSearchQuery(''); setSearchResults([]); }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SearchIcon /> Search Elements
        </DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            placeholder="Search by text content..."
            value={searchQuery}
            onChange={(e) => handleSearch(e.target.value)}
            sx={{ mb: 2 }}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
            }}
          />
          {searchResults.length > 0 ? (
            <Box sx={{ maxHeight: 300, overflow: 'auto' }}>
              {searchResults.map(el => (
                <Paper
                  key={el.element_id}
                  onClick={() => navigateToElement(el)}
                  sx={{
                    p: 2, mb: 1, cursor: 'pointer',
                    '&:hover': { bgcolor: alpha('#3b82f6', 0.1) }
                  }}
                >
                  <Typography variant="subtitle2" sx={{ textTransform: 'capitalize' }}>
                    {el.element_type} {el.label ? `- ${el.label}` : ''}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" noWrap>
                    {el.content || el.checklist_items?.map(i => i.text).join(', ') || 'No content'}
                  </Typography>
                </Paper>
              ))}
            </Box>
          ) : searchQuery ? (
            <Typography color="text.secondary">No elements found matching "{searchQuery}"</Typography>
          ) : (
            <Typography color="text.secondary">Type to search for elements by their text content</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setSearchOpen(false); setSearchQuery(''); setSearchResults([]); }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* AI Features Dialog */}
      <Dialog
        open={aiDialogOpen}
        onClose={() => { setAiDialogOpen(false); setAiResult(''); setAiPrompt(''); }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <AutoFixHighIcon sx={{ color: '#8b5cf6' }} /> AI Features
        </DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', gap: 1, mb: 3, flexWrap: 'wrap' }}>
            <Button
              variant={aiDialogMode === 'summarize' ? 'contained' : 'outlined'}
              onClick={() => { setAiDialogMode('summarize'); setAiResult(''); }}
              startIcon={<SummarizeIcon />}
              sx={{ flex: 1, minWidth: 100 }}
            >
              Summarize
            </Button>
            <Button
              variant={aiDialogMode === 'categorize' ? 'contained' : 'outlined'}
              onClick={() => { setAiDialogMode('categorize'); setAiResult(''); }}
              startIcon={<CategoryOutlinedIcon />}
              sx={{ flex: 1, minWidth: 100 }}
            >
              Categorize
            </Button>
            <Button
              variant={aiDialogMode === 'generate' ? 'contained' : 'outlined'}
              onClick={() => { setAiDialogMode('generate'); setAiResult(''); }}
              startIcon={<LightbulbIcon />}
              sx={{ flex: 1, minWidth: 100 }}
            >
              Generate
            </Button>
            <Button
              variant={aiDialogMode === 'autolayout' ? 'contained' : 'outlined'}
              onClick={() => { setAiDialogMode('autolayout'); setAiResult(''); }}
              startIcon={<ViewModuleIcon />}
              sx={{ flex: 1, minWidth: 100 }}
            >
              Auto-Layout
            </Button>
          </Box>

          {aiDialogMode === 'summarize' && (
            <Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Summarize all sticky notes on the whiteboard into key themes and actionable insights.
              </Typography>
              <Button
                variant="contained"
                onClick={handleAiSummarize}
                disabled={aiLoading}
                fullWidth
                sx={{ bgcolor: '#8b5cf6', '&:hover': { bgcolor: '#7c3aed' } }}
              >
                {aiLoading ? 'Analyzing...' : 'Summarize Sticky Notes'}
              </Button>
            </Box>
          )}

          {aiDialogMode === 'categorize' && (
            <Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Automatically categorize sticky notes and add category badges to help organize your ideas.
              </Typography>
              <Button
                variant="contained"
                onClick={handleAiCategorize}
                disabled={aiLoading}
                fullWidth
                sx={{ bgcolor: '#8b5cf6', '&:hover': { bgcolor: '#7c3aed' } }}
              >
                {aiLoading ? 'Categorizing...' : 'Auto-Categorize Stickies'}
              </Button>
            </Box>
          )}

          {aiDialogMode === 'generate' && (
            <Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Generate brainstorming ideas as sticky notes based on your prompt.
              </Typography>
              <TextField
                fullWidth
                multiline
                rows={2}
                placeholder="Enter a topic (e.g., 'Ways to improve team productivity')"
                value={aiPrompt}
                onChange={(e) => setAiPrompt(e.target.value)}
                sx={{ mb: 2 }}
              />
              <Button
                variant="contained"
                onClick={handleAiGenerate}
                disabled={aiLoading || !aiPrompt.trim()}
                fullWidth
                sx={{ bgcolor: '#8b5cf6', '&:hover': { bgcolor: '#7c3aed' } }}
              >
                {aiLoading ? 'Generating...' : 'Generate Ideas'}
              </Button>
            </Box>
          )}

          {aiDialogMode === 'autolayout' && (
            <Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Use AI to automatically arrange elements on the whiteboard for better organization and visual clarity.
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                <Chip
                  label="Grid Layout"
                  onClick={() => setAiPrompt('grid')}
                  variant={aiPrompt === 'grid' ? 'filled' : 'outlined'}
                  color="primary"
                />
                <Chip
                  label="Horizontal Flow"
                  onClick={() => setAiPrompt('horizontal')}
                  variant={aiPrompt === 'horizontal' ? 'filled' : 'outlined'}
                  color="primary"
                />
                <Chip
                  label="Vertical Flow"
                  onClick={() => setAiPrompt('vertical')}
                  variant={aiPrompt === 'vertical' ? 'filled' : 'outlined'}
                  color="primary"
                />
                <Chip
                  label="Cluster by Type"
                  onClick={() => setAiPrompt('cluster')}
                  variant={aiPrompt === 'cluster' ? 'filled' : 'outlined'}
                  color="primary"
                />
                <Chip
                  label="Mind Map"
                  onClick={() => setAiPrompt('mindmap')}
                  variant={aiPrompt === 'mindmap' ? 'filled' : 'outlined'}
                  color="primary"
                />
              </Box>
              <Button
                variant="contained"
                onClick={handleAutoLayout}
                disabled={aiLoading || !aiPrompt}
                fullWidth
                sx={{ bgcolor: '#8b5cf6', '&:hover': { bgcolor: '#7c3aed' } }}
              >
                {aiLoading ? 'Arranging...' : 'Apply Auto-Layout'}
              </Button>
            </Box>
          )}

          {aiResult && (
            <Paper sx={{ mt: 3, p: 2, bgcolor: alpha('#8b5cf6', 0.1), maxHeight: 300, overflow: 'auto' }}>
              <Typography variant="subtitle2" sx={{ mb: 1, color: '#8b5cf6' }}>Result:</Typography>
              <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>{aiResult}</Typography>
            </Paper>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setAiDialogOpen(false); setAiResult(''); setAiPrompt(''); }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Gradient Dialog */}
      <Dialog
        open={gradientDialogOpen}
        onClose={() => setGradientDialogOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <GradientIcon /> Gradient Fill
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Select a gradient preset to apply to the selected shape:
          </Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 1.5 }}>
            {GRADIENT_PRESETS.map(({ name, start, end }) => (
              <Paper
                key={name}
                onClick={() => applyGradient({ start, end, direction: 'diagonal' })}
                sx={{
                  p: 1.5,
                  cursor: 'pointer',
                  textAlign: 'center',
                  '&:hover': { transform: 'scale(1.02)' },
                  transition: 'transform 0.2s'
                }}
              >
                <Box
                  sx={{
                    height: 40,
                    borderRadius: 1,
                    mb: 1,
                    background: `linear-gradient(135deg, ${start} 0%, ${end} 100%)`
                  }}
                />
                <Typography variant="caption">{name}</Typography>
              </Paper>
            ))}
          </Box>
          <Divider sx={{ my: 2 }} />
          <Typography variant="subtitle2" sx={{ mb: 1 }}>Direction:</Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={() => selectedElement && applyGradient({
                start: selectedGradient?.start || '#3b82f6',
                end: selectedGradient?.end || '#8b5cf6',
                direction: 'horizontal'
              })}
            >
              Horizontal
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => selectedElement && applyGradient({
                start: selectedGradient?.start || '#3b82f6',
                end: selectedGradient?.end || '#8b5cf6',
                direction: 'vertical'
              })}
            >
              Vertical
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => selectedElement && applyGradient({
                start: selectedGradient?.start || '#3b82f6',
                end: selectedGradient?.end || '#8b5cf6',
                direction: 'diagonal'
              })}
            >
              Diagonal
            </Button>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setGradientDialogOpen(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>

      {/* Link Creation Dialog */}
      <Dialog
        open={linkDialogOpen}
        onClose={() => { setLinkDialogOpen(false); setLinkUrl(''); setLinkTitle(''); setPendingLinkPosition(null); }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <LaunchIcon sx={{ color: '#3b82f6' }} /> Add Link/URL Card
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Create a clickable link card that can be opened in a new tab.
          </Typography>
          <TextField
            fullWidth
            label="URL"
            placeholder="https://example.com"
            value={linkUrl}
            onChange={(e) => setLinkUrl(e.target.value)}
            sx={{ mb: 2 }}
            autoFocus
          />
          <TextField
            fullWidth
            label="Title (optional)"
            placeholder="Link title"
            value={linkTitle}
            onChange={(e) => setLinkTitle(e.target.value)}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setLinkDialogOpen(false); setLinkUrl(''); setLinkTitle(''); setPendingLinkPosition(null); }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleCreateLink}
            disabled={!linkUrl.trim()}
            sx={{ bgcolor: '#3b82f6', '&:hover': { bgcolor: '#2563eb' } }}
          >
            Create Link
          </Button>
        </DialogActions>
      </Dialog>

      {/* Comments Panel Drawer */}
      <Drawer
        anchor="right"
        open={commentsPanelOpen}
        onClose={() => { setCommentsPanelOpen(false); setCommentingElement(null); setNewCommentText(''); }}
      >
        <Box sx={{ width: 360, p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CommentIcon /> Comments
            </Typography>
            <IconButton onClick={() => setCommentsPanelOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          
          {commentingElement && (
            <>
              <Paper sx={{ p: 1.5, mb: 2, bgcolor: alpha('#3b82f6', 0.1) }}>
                <Typography variant="caption" color="text.secondary">
                  Commenting on: {commentingElement.element_type}
                </Typography>
                {commentingElement.label && (
                  <Typography variant="body2" sx={{ fontWeight: 'bold', mt: 0.5 }}>
                    "{commentingElement.label}"
                  </Typography>
                )}
              </Paper>

              <Box sx={{ flex: 1, overflowY: 'auto', mb: 2 }}>
                {(!commentingElement.comments || commentingElement.comments.length === 0) ? (
                  <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                    No comments yet. Be the first to add one!
                  </Typography>
                ) : (
                  commentingElement.comments.map((comment) => (
                    <Paper key={comment.id} sx={{ p: 1.5, mb: 1, position: 'relative' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                        <PersonIcon sx={{ fontSize: 18, color: '#3b82f6' }} />
                        <Typography variant="subtitle2">{comment.username}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(comment.created_at).toLocaleString()}
                        </Typography>
                        <IconButton
                          size="small"
                          onClick={() => deleteComment(comment.id)}
                          sx={{ ml: 'auto' }}
                        >
                          <DeleteIcon sx={{ fontSize: 16 }} />
                        </IconButton>
                      </Box>
                      <Typography variant="body2">{comment.text}</Typography>
                      {comment.mentions && comment.mentions.length > 0 && (
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                          {comment.mentions.map((userId) => {
                            const user = collaborators.find(c => c.user_id === userId);
                            return user ? (
                              <Chip
                                key={userId}
                                label={`@${user.username}`}
                                size="small"
                                icon={<AlternateEmailIcon sx={{ fontSize: 14 }} />}
                                sx={{ fontSize: 11 }}
                              />
                            ) : null;
                          })}
                        </Box>
                      )}
                    </Paper>
                  ))
                )}
              </Box>

              <Box sx={{ mt: 'auto' }}>
                <TextField
                  fullWidth
                  multiline
                  rows={2}
                  placeholder="Add a comment... Use @username to mention"
                  value={newCommentText}
                  onChange={(e) => {
                    setNewCommentText(e.target.value);
                    handleMentionInput(e.target.value);
                  }}
                  sx={{ mb: 1 }}
                />
                <Button
                  fullWidth
                  variant="contained"
                  onClick={addComment}
                  disabled={!newCommentText.trim()}
                  startIcon={<SendIcon />}
                  sx={{ bgcolor: '#3b82f6', '&:hover': { bgcolor: '#2563eb' } }}
                >
                  Post Comment
                </Button>
              </Box>

              {/* Mentions Autocomplete */}
              <Popover
                open={Boolean(mentionsAnchor)}
                anchorEl={mentionsAnchor}
                onClose={() => { setMentionsAnchor(null); setMentionQuery(''); }}
                anchorOrigin={{ vertical: 'top', horizontal: 'left' }}
                transformOrigin={{ vertical: 'bottom', horizontal: 'left' }}
              >
                <Box sx={{ p: 1, maxHeight: 200, overflowY: 'auto', width: 200 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ px: 1 }}>
                    Mention someone:
                  </Typography>
                  {collaborators
                    .filter(c => c.username.toLowerCase().includes(mentionQuery.toLowerCase()))
                    .map((user) => (
                      <MenuItem
                        key={user.user_id}
                        onClick={() => insertMention(user.username)}
                        sx={{ py: 0.5 }}
                      >
                        <PersonIcon sx={{ fontSize: 18, mr: 1, color: '#3b82f6' }} />
                        <Typography variant="body2">{user.username}</Typography>
                      </MenuItem>
                    ))}
                  {collaborators.filter(c => c.username.toLowerCase().includes(mentionQuery.toLowerCase())).length === 0 && (
                    <Typography variant="body2" color="text.secondary" sx={{ p: 1 }}>
                      No matches found
                    </Typography>
                  )}
                </Box>
              </Popover>
            </>
          )}
        </Box>
      </Drawer>

      {/* Sticky Note Size Menu */}
      <Menu
        anchorEl={stickySizeMenuAnchor}
        open={Boolean(stickySizeMenuAnchor)}
        onClose={() => setStickySizeMenuAnchor(null)}
      >
        <Typography variant="subtitle2" sx={{ px: 2, py: 1, color: 'text.secondary' }}>
          Sticky Note Size
        </Typography>
        <MenuItem onClick={() => changeStickySize('small')}>
          <PhotoSizeSelectSmallIcon sx={{ mr: 1, fontSize: 18 }} />
          Small ({STICKY_SIZES.small.width}×{STICKY_SIZES.small.height})
        </MenuItem>
        <MenuItem onClick={() => changeStickySize('medium')}>
          <AspectRatioIcon sx={{ mr: 1, fontSize: 18 }} />
          Medium ({STICKY_SIZES.medium.width}×{STICKY_SIZES.medium.height})
        </MenuItem>
        <MenuItem onClick={() => changeStickySize('large')}>
          <PhotoSizeSelectLargeIcon sx={{ mr: 1, fontSize: 18 }} />
          Large ({STICKY_SIZES.large.width}×{STICKY_SIZES.large.height})
        </MenuItem>
      </Menu>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={3000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbar.severity} variant="filled" onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>

      {/* Keyboard shortcuts help - bottom left */}
      <Paper
        sx={{
          position: 'fixed',
          bottom: 16,
          left: 16,
          p: 1.5,
          bgcolor: alpha('#1e1e2e', 0.9),
          backdropFilter: 'blur(10px)',
          border: `1px solid ${alpha('#ffffff', 0.1)}`,
          borderRadius: 2,
          maxWidth: 280,
        }}
      >
        <Typography variant="caption" sx={{ fontWeight: 600, color: 'text.secondary', display: 'block', mb: 0.5 }}>
          Shortcuts
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 0.25, fontSize: '0.65rem' }}>
          <Typography variant="caption" color="text.secondary">V - Select</Typography>
          <Typography variant="caption" color="text.secondary">H - Pan</Typography>
          <Typography variant="caption" color="text.secondary">R - Rectangle</Typography>
          <Typography variant="caption" color="text.secondary">O - Ellipse</Typography>
          <Typography variant="caption" color="text.secondary">L - Line</Typography>
          <Typography variant="caption" color="text.secondary">A - Arrow</Typography>
          <Typography variant="caption" color="text.secondary">T - Text</Typography>
          <Typography variant="caption" color="text.secondary">S - Sticky</Typography>
          <Typography variant="caption" color="text.secondary">P - Pencil</Typography>
          <Typography variant="caption" color="text.secondary">E - Eraser</Typography>
          <Typography variant="caption" color="text.secondary">G - Grid</Typography>
          <Typography variant="caption" color="text.secondary">⇧G - Snap</Typography>
          <Typography variant="caption" color="text.secondary">F - Fit</Typography>
          <Typography variant="caption" color="text.secondary">F11 - Fullscreen</Typography>
          <Typography variant="caption" color="text.secondary">^A - Select All</Typography>
          <Typography variant="caption" color="text.secondary">^D - Duplicate</Typography>
          <Typography variant="caption" color="text.secondary">^L - Lock</Typography>
          <Typography variant="caption" color="text.secondary">^C - Copy</Typography>
          <Typography variant="caption" color="text.secondary">^V - Paste</Typography>
          <Typography variant="caption" color="text.secondary">Del - Delete</Typography>
          <Typography variant="caption" color="text.secondary">⇧Click - Multi</Typography>
          <Typography variant="caption" color="text.secondary">Drag - Box Select</Typography>
        </Box>
      </Paper>
    </Box>
  );
};

export default WhiteboardPage;
