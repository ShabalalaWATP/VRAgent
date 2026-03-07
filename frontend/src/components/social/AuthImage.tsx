import { useState, useEffect, useRef } from 'react';
import { Box, Skeleton } from '@mui/material';
import { getAuthHeadersNoContentType } from '../../api/client';

interface AuthImageProps {
  src: string | undefined;
  alt?: string;
  sx?: Record<string, any>;
  style?: React.CSSProperties;
  loading?: 'lazy' | 'eager';
  onClick?: (e: React.MouseEvent) => void;
}

/**
 * Image component that fetches images using authenticated requests.
 * Needed because secure file endpoints require JWT auth headers,
 * which plain <img src="..."> tags don't send.
 */
export function AuthImage({ src, alt, sx, style, loading, onClick }: AuthImageProps) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const urlRef = useRef<string | null>(null);

  useEffect(() => {
    // Reset state when src changes
    setBlobUrl(null);
    setError(false);

    if (!src) {
      setError(true);
      return;
    }

    let cancelled = false;

    const fetchImage = async () => {
      try {
        const response = await fetch(src, {
          headers: getAuthHeadersNoContentType(),
        });
        if (cancelled) return;
        if (!response.ok) {
          console.error(`AuthImage: failed to fetch ${src} — ${response.status}`);
          setError(true);
          return;
        }
        const blob = await response.blob();
        if (cancelled) return;
        const url = URL.createObjectURL(blob);
        urlRef.current = url;
        setBlobUrl(url);
      } catch (err) {
        if (!cancelled) {
          console.error('AuthImage: fetch error', err);
          setError(true);
        }
      }
    };

    fetchImage();

    return () => {
      cancelled = true;
      if (urlRef.current) {
        URL.revokeObjectURL(urlRef.current);
        urlRef.current = null;
      }
    };
  }, [src]);

  if (error) {
    return (
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: 'action.hover',
          borderRadius: 1,
          minHeight: 60,
          minWidth: 60,
          ...sx,
        }}
        style={style}
      >
        <Box component="span" sx={{ fontSize: '0.75rem', opacity: 0.5 }}>
          Image failed to load
        </Box>
      </Box>
    );
  }

  if (!blobUrl) {
    return <Skeleton variant="rectangular" sx={{ borderRadius: 1, maxHeight: 200, ...sx }} width="100%" height={120} />;
  }

  if (sx) {
    return (
      <Box
        component="img"
        src={blobUrl}
        alt={alt}
        onClick={onClick}
        sx={sx}
      />
    );
  }

  return (
    <img
      src={blobUrl}
      alt={alt}
      style={style}
      loading={loading}
      onClick={onClick}
    />
  );
}
