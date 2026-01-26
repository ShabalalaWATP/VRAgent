import React, { useMemo } from 'react';
import {
  Box,
  Typography,
  Paper,
  Chip,
  Stack,
  CircularProgress,
  useTheme,
} from '@mui/material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  ReferenceLine,
  Area,
  ComposedChart,
} from 'recharts';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import TrendingDownIcon from '@mui/icons-material/TrendingDown';
import PauseIcon from '@mui/icons-material/Pause';

interface TimelinePoint {
  timestamp: string;
  elapsed_sec: number;
  edges_total: number;
  edges_new: number;
  blocks_hit?: number;
  exec_count?: number;
  corpus_size?: number;
  crashes?: number;
  hangs?: number;
}

interface CoverageTrendData {
  timeline: TimelinePoint[];
  growth_rate: number;
  average_growth_rate: number;
  plateau_detected: boolean;
  plateau_start_time: number | null;
  predicted_saturation: number | null;
  total_duration_sec: number;
  peak_edges: number;
  final_coverage_pct?: number;
}

interface CoverageTrendChartProps {
  data: CoverageTrendData | null;
  loading?: boolean;
  height?: number;
  showCorpusSize?: boolean;
  showCrashes?: boolean;
  showGrowthRate?: boolean;
}

const formatTime = (seconds: number): string => {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
};

const formatNumber = (num: number): string => {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
};

export const CoverageTrendChart: React.FC<CoverageTrendChartProps> = ({
  data,
  loading = false,
  height = 300,
  showCorpusSize = true,
  showCrashes = true,
  showGrowthRate = true,
}) => {
  const theme = useTheme();

  const chartData = useMemo(() => {
    if (!data || !data.timeline || data.timeline.length === 0) return [];

    return data.timeline.map((point) => ({
      time: point.elapsed_sec,
      timeLabel: formatTime(point.elapsed_sec),
      edges: point.edges_total,
      newEdges: point.edges_new,
      corpusSize: point.corpus_size || 0,
      crashes: point.crashes || 0,
      hangs: point.hangs || 0,
      execCount: point.exec_count || 0,
    }));
  }, [data]);

  const getGrowthIndicator = () => {
    if (!data) return null;

    if (data.plateau_detected) {
      return (
        <Chip
          icon={<PauseIcon />}
          label="Plateau"
          color="warning"
          size="small"
          variant="outlined"
        />
      );
    }

    if (data.growth_rate > 0.1) {
      return (
        <Chip
          icon={<TrendingUpIcon />}
          label={`+${data.growth_rate.toFixed(2)} edges/s`}
          color="success"
          size="small"
          variant="outlined"
        />
      );
    }

    if (data.growth_rate > 0) {
      return (
        <Chip
          icon={<TrendingUpIcon />}
          label={`+${data.growth_rate.toFixed(4)} edges/s`}
          color="info"
          size="small"
          variant="outlined"
        />
      );
    }

    return (
      <Chip
        icon={<TrendingDownIcon />}
        label="Stagnant"
        color="error"
        size="small"
        variant="outlined"
      />
    );
  };

  if (loading) {
    return (
      <Paper
        sx={{
          p: 3,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: height + 60,
          bgcolor: '#1a1a1a',
        }}
      >
        <CircularProgress size={40} />
      </Paper>
    );
  }

  if (!data || chartData.length === 0) {
    return (
      <Paper
        sx={{
          p: 3,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: height + 60,
          bgcolor: '#1a1a1a',
        }}
      >
        <Typography color="text.secondary">No timeline data available</Typography>
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 2, bgcolor: '#1a1a1a' }}>
      <Stack spacing={2}>
        {/* Header */}
        <Stack direction="row" justifyContent="space-between" alignItems="center" flexWrap="wrap" gap={1}>
          <Typography variant="subtitle1" fontWeight="bold">
            Coverage Timeline
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            {showGrowthRate && getGrowthIndicator()}
            <Chip
              label={`Peak: ${formatNumber(data.peak_edges)} edges`}
              size="small"
              variant="outlined"
            />
            <Chip
              label={`Duration: ${formatTime(data.total_duration_sec)}`}
              size="small"
              variant="outlined"
            />
            {data.predicted_saturation && (
              <Chip
                label={`Est. Max: ${formatNumber(data.predicted_saturation)}`}
                size="small"
                color="info"
                variant="outlined"
              />
            )}
          </Stack>
        </Stack>

        {/* Chart */}
        <Box sx={{ width: '100%', height }}>
          <ResponsiveContainer>
            <ComposedChart data={chartData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#333" />
              <XAxis
                dataKey="time"
                tickFormatter={formatTime}
                stroke="#888"
                tick={{ fill: '#888', fontSize: 11 }}
              />
              <YAxis
                yAxisId="left"
                stroke="#4CAF50"
                tick={{ fill: '#888', fontSize: 11 }}
                tickFormatter={formatNumber}
              />
              {(showCorpusSize || showCrashes) && (
                <YAxis
                  yAxisId="right"
                  orientation="right"
                  stroke="#2196F3"
                  tick={{ fill: '#888', fontSize: 11 }}
                />
              )}
              <Tooltip
                contentStyle={{
                  backgroundColor: '#2a2a2a',
                  border: '1px solid #444',
                  borderRadius: 4,
                }}
                labelFormatter={(value) => `Time: ${formatTime(value as number)}`}
                formatter={(value: number, name: string) => {
                  const labels: Record<string, string> = {
                    edges: 'Total Edges',
                    corpusSize: 'Corpus Size',
                    crashes: 'Crashes',
                  };
                  return [formatNumber(value), labels[name] || name];
                }}
              />
              <Legend />

              {/* Plateau line */}
              {data.plateau_detected && data.plateau_start_time && (
                <ReferenceLine
                  x={data.plateau_start_time}
                  stroke="#FF9800"
                  strokeDasharray="5 5"
                  label={{
                    value: 'Plateau',
                    fill: '#FF9800',
                    fontSize: 10,
                  }}
                  yAxisId="left"
                />
              )}

              {/* Predicted saturation line */}
              {data.predicted_saturation && (
                <ReferenceLine
                  y={data.predicted_saturation}
                  stroke="#9C27B0"
                  strokeDasharray="3 3"
                  label={{
                    value: `Est. Max: ${formatNumber(data.predicted_saturation)}`,
                    fill: '#9C27B0',
                    fontSize: 10,
                    position: 'right',
                  }}
                  yAxisId="left"
                />
              )}

              {/* Main edges line with area fill */}
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="edges"
                stroke="#4CAF50"
                fill="#4CAF5030"
                strokeWidth={2}
                name="edges"
              />

              {/* Corpus size */}
              {showCorpusSize && (
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="corpusSize"
                  stroke="#2196F3"
                  strokeWidth={1}
                  dot={false}
                  name="corpusSize"
                />
              )}

              {/* Crashes */}
              {showCrashes && (
                <Line
                  yAxisId="right"
                  type="stepAfter"
                  dataKey="crashes"
                  stroke="#F44336"
                  strokeWidth={2}
                  dot={false}
                  name="crashes"
                />
              )}
            </ComposedChart>
          </ResponsiveContainer>
        </Box>

        {/* Stats Row */}
        <Stack direction="row" spacing={3} justifyContent="center" flexWrap="wrap">
          <Stack alignItems="center">
            <Typography variant="h6" color="success.main">
              {formatNumber(data.peak_edges)}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Total Edges
            </Typography>
          </Stack>
          <Stack alignItems="center">
            <Typography variant="h6" color="info.main">
              {data.average_growth_rate.toFixed(4)}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Avg Growth (edges/s)
            </Typography>
          </Stack>
          {data.final_coverage_pct !== undefined && (
            <Stack alignItems="center">
              <Typography variant="h6" color="warning.main">
                {data.final_coverage_pct.toFixed(1)}%
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Coverage
              </Typography>
            </Stack>
          )}
          {data.plateau_detected && data.plateau_start_time && (
            <Stack alignItems="center">
              <Typography variant="h6" color="warning.main">
                {formatTime(data.plateau_start_time)}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Plateau Start
              </Typography>
            </Stack>
          )}
        </Stack>
      </Stack>
    </Paper>
  );
};

export default CoverageTrendChart;
