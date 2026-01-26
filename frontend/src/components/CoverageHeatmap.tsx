import React, { useMemo, useRef, useEffect } from 'react';
import { Box, Typography, Paper, Tooltip, Chip, Stack, CircularProgress } from '@mui/material';

interface CoverageHeatmapData {
  width: number;
  height: number;
  data: number[][];
  min_value: number;
  max_value: number;
  total_edges: number;
  covered_edges: number;
  coverage_percentage: number;
  color_scheme?: string;
}

interface CoverageHeatmapProps {
  data: CoverageHeatmapData | null;
  loading?: boolean;
  width?: number;
  height?: number;
  colorScheme?: 'viridis' | 'plasma' | 'inferno';
  showLegend?: boolean;
  onCellClick?: (x: number, y: number, value: number) => void;
}

// Color schemes
const viridisColors = [
  [68, 1, 84],
  [72, 40, 120],
  [62, 73, 137],
  [49, 104, 142],
  [38, 130, 142],
  [31, 158, 137],
  [53, 183, 121],
  [109, 205, 89],
  [180, 222, 44],
  [253, 231, 37],
];

const plasmaColors = [
  [13, 8, 135],
  [75, 3, 161],
  [125, 3, 168],
  [168, 34, 150],
  [203, 70, 121],
  [229, 107, 93],
  [248, 148, 65],
  [253, 191, 47],
  [240, 230, 33],
  [240, 249, 33],
];

const infernoColors = [
  [0, 0, 4],
  [40, 11, 84],
  [101, 21, 110],
  [159, 42, 99],
  [212, 72, 66],
  [245, 125, 21],
  [250, 175, 12],
  [245, 219, 76],
  [252, 255, 164],
];

const colorSchemes: Record<string, number[][]> = {
  viridis: viridisColors,
  plasma: plasmaColors,
  inferno: infernoColors,
};

function getColor(value: number, maxValue: number, scheme: string, logScale: boolean = true): string {
  if (value === 0) {
    return 'rgb(20, 20, 20)'; // Dark background for uncovered
  }

  const colors = colorSchemes[scheme] || viridisColors;
  let normalizedValue: number;

  if (logScale && value > 0) {
    normalizedValue = Math.log1p(value) / Math.log1p(maxValue);
  } else {
    normalizedValue = value / maxValue;
  }

  normalizedValue = Math.max(0, Math.min(1, normalizedValue));

  const idx = Math.min(Math.floor(normalizedValue * (colors.length - 1)), colors.length - 2);
  const frac = normalizedValue * (colors.length - 1) - idx;

  const r = Math.round(colors[idx][0] + frac * (colors[idx + 1][0] - colors[idx][0]));
  const g = Math.round(colors[idx][1] + frac * (colors[idx + 1][1] - colors[idx][1]));
  const b = Math.round(colors[idx][2] + frac * (colors[idx + 1][2] - colors[idx][2]));

  return `rgb(${r}, ${g}, ${b})`;
}

export const CoverageHeatmap: React.FC<CoverageHeatmapProps> = ({
  data,
  loading = false,
  width = 256,
  height = 256,
  colorScheme = 'viridis',
  showLegend = true,
  onCellClick,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const cellSize = useMemo(() => {
    if (!data || !data.data || data.data.length === 0) return { w: 1, h: 1 };
    const rows = data.data.length;
    const cols = data.data[0]?.length || 1;
    return {
      w: width / cols,
      h: height / rows,
    };
  }, [data, width, height]);

  useEffect(() => {
    if (!canvasRef.current || !data || !data.data || data.data.length === 0) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rows = data.data.length;
    const cols = data.data[0]?.length || 1;
    const maxValue = data.max_value || 1;

    // Clear canvas
    ctx.fillStyle = '#1a1a1a';
    ctx.fillRect(0, 0, width, height);

    // Draw heatmap cells
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const value = data.data[y]?.[x] || 0;
        ctx.fillStyle = getColor(value, maxValue, colorScheme);
        ctx.fillRect(
          x * cellSize.w,
          y * cellSize.h,
          cellSize.w,
          cellSize.h
        );
      }
    }
  }, [data, width, height, colorScheme, cellSize]);

  const handleCanvasClick = (event: React.MouseEvent<HTMLCanvasElement>) => {
    if (!data || !data.data || !onCellClick) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = Math.floor((event.clientX - rect.left) / cellSize.w);
    const y = Math.floor((event.clientY - rect.top) / cellSize.h);

    if (y >= 0 && y < data.data.length && x >= 0 && x < (data.data[0]?.length || 0)) {
      const value = data.data[y][x];
      onCellClick(x, y, value);
    }
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

  if (!data) {
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
        <Typography color="text.secondary">No coverage data available</Typography>
      </Paper>
    );
  }

  return (
    <Paper sx={{ p: 2, bgcolor: '#1a1a1a' }}>
      <Stack spacing={2}>
        {/* Header */}
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Typography variant="subtitle1" fontWeight="bold">
            Coverage Heatmap
          </Typography>
          <Stack direction="row" spacing={1}>
            <Chip
              label={`${data.coverage_percentage.toFixed(1)}%`}
              color={data.coverage_percentage > 50 ? 'success' : 'warning'}
              size="small"
            />
            <Chip
              label={`${data.covered_edges.toLocaleString()} / ${data.total_edges.toLocaleString()} edges`}
              variant="outlined"
              size="small"
            />
          </Stack>
        </Stack>

        {/* Canvas */}
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            border: '1px solid #333',
            borderRadius: 1,
            overflow: 'hidden',
          }}
        >
          <Tooltip title="Click to inspect cell coverage">
            <canvas
              ref={canvasRef}
              width={width}
              height={height}
              onClick={handleCanvasClick}
              style={{ cursor: onCellClick ? 'crosshair' : 'default' }}
            />
          </Tooltip>
        </Box>

        {/* Legend */}
        {showLegend && (
          <Stack direction="row" spacing={1} justifyContent="center" alignItems="center">
            <Typography variant="caption" color="text.secondary">
              Low
            </Typography>
            <Box
              sx={{
                display: 'flex',
                height: 12,
                width: 150,
                borderRadius: 0.5,
                overflow: 'hidden',
              }}
            >
              {Array.from({ length: 10 }).map((_, i) => (
                <Box
                  key={i}
                  sx={{
                    flex: 1,
                    bgcolor: getColor(i + 1, 10, colorScheme, false),
                  }}
                />
              ))}
            </Box>
            <Typography variant="caption" color="text.secondary">
              High
            </Typography>
          </Stack>
        )}
      </Stack>
    </Paper>
  );
};

export default CoverageHeatmap;
