import React, { useState, useCallback, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  IconButton,
  Box,
  Typography,
  ImageList,
  ImageListItem,
  useTheme,
  useMediaQuery,
  Fade,
  Zoom,
  Paper,
} from '@mui/material';
import {
  Close as CloseIcon,
  ChevronLeft as PrevIcon,
  ChevronRight as NextIcon,
  ZoomIn as ZoomInIcon,
  ZoomOut as ZoomOutIcon,
  Download as DownloadIcon,
  GridView as GridIcon,
  Fullscreen as FullscreenIcon,
  FullscreenExit as FullscreenExitIcon,
} from '@mui/icons-material';

export interface GalleryImage {
  id: number; // message ID
  url: string;
  filename: string;
  thumbnailUrl?: string;
  senderUsername: string;
  createdAt: string;
  width?: number;
  height?: number;
}

interface ImageGalleryProps {
  images: GalleryImage[];
  open: boolean;
  initialIndex?: number;
  onClose: () => void;
  onNavigateToMessage?: (messageId: number) => void;
}

export function ImageGallery({
  images,
  open,
  initialIndex = 0,
  onClose,
  onNavigateToMessage,
}: ImageGalleryProps) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const [currentIndex, setCurrentIndex] = useState(initialIndex);
  const [zoom, setZoom] = useState(1);
  const [showGrid, setShowGrid] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [position, setPosition] = useState({ x: 0, y: 0 });

  const currentImage = images[currentIndex];

  // Reset state when opening
  useEffect(() => {
    if (open) {
      setCurrentIndex(initialIndex);
      setZoom(1);
      setPosition({ x: 0, y: 0 });
      setShowGrid(false);
    }
  }, [open, initialIndex]);

  // Keyboard navigation
  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case 'ArrowLeft':
          handlePrev();
          break;
        case 'ArrowRight':
          handleNext();
          break;
        case 'Escape':
          if (showGrid) {
            setShowGrid(false);
          } else {
            onClose();
          }
          break;
        case '+':
        case '=':
          handleZoomIn();
          break;
        case '-':
          handleZoomOut();
          break;
        case 'g':
          setShowGrid((prev) => !prev);
          break;
        case 'f':
          toggleFullscreen();
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, currentIndex, images.length, showGrid]);

  const handlePrev = useCallback(() => {
    setCurrentIndex((prev) => (prev > 0 ? prev - 1 : images.length - 1));
    setZoom(1);
    setPosition({ x: 0, y: 0 });
  }, [images.length]);

  const handleNext = useCallback(() => {
    setCurrentIndex((prev) => (prev < images.length - 1 ? prev + 1 : 0));
    setZoom(1);
    setPosition({ x: 0, y: 0 });
  }, [images.length]);

  const handleZoomIn = () => {
    setZoom((prev) => Math.min(prev + 0.5, 4));
  };

  const handleZoomOut = () => {
    setZoom((prev) => {
      const newZoom = Math.max(prev - 0.5, 1);
      if (newZoom === 1) {
        setPosition({ x: 0, y: 0 });
      }
      return newZoom;
    });
  };

  const handleDownload = async () => {
    if (!currentImage) return;
    try {
      const response = await fetch(currentImage.url);
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = currentImage.filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Failed to download image:', error);
    }
  };

  const toggleFullscreen = async () => {
    if (!document.fullscreenElement) {
      await document.documentElement.requestFullscreen();
      setIsFullscreen(true);
    } else {
      await document.exitFullscreen();
      setIsFullscreen(false);
    }
  };

  // Pan functionality for zoomed images
  const handleMouseDown = (e: React.MouseEvent) => {
    if (zoom > 1) {
      setIsDragging(true);
      setDragStart({ x: e.clientX - position.x, y: e.clientY - position.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isDragging && zoom > 1) {
      setPosition({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleGridSelect = (index: number) => {
    setCurrentIndex(index);
    setShowGrid(false);
    setZoom(1);
    setPosition({ x: 0, y: 0 });
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (!currentImage) return null;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth={false}
      fullScreen
      PaperProps={{
        sx: {
          bgcolor: 'rgba(0, 0, 0, 0.95)',
          backdropFilter: 'blur(10px)',
        },
      }}
    >
      <DialogContent
        sx={{
          p: 0,
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          overflow: 'hidden',
          userSelect: 'none',
        }}
      >
        {/* Top toolbar */}
        <Fade in={!showGrid}>
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              p: 2,
              background: 'linear-gradient(to bottom, rgba(0,0,0,0.7), transparent)',
              zIndex: 10,
            }}
          >
            {/* Image info */}
            <Box>
              <Typography variant="subtitle1" color="white">
                {currentImage.filename}
              </Typography>
              <Typography variant="caption" color="grey.400">
                {currentImage.senderUsername} • {formatDate(currentImage.createdAt)}
              </Typography>
            </Box>

            {/* Counter and actions */}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" color="grey.400">
                {currentIndex + 1} / {images.length}
              </Typography>
              
              <IconButton onClick={handleZoomOut} disabled={zoom <= 1} sx={{ color: 'white' }}>
                <ZoomOutIcon />
              </IconButton>
              <Typography variant="body2" color="white" sx={{ minWidth: 50, textAlign: 'center' }}>
                {Math.round(zoom * 100)}%
              </Typography>
              <IconButton onClick={handleZoomIn} disabled={zoom >= 4} sx={{ color: 'white' }}>
                <ZoomInIcon />
              </IconButton>
              
              {images.length > 1 && (
                <IconButton onClick={() => setShowGrid(true)} sx={{ color: 'white' }}>
                  <GridIcon />
                </IconButton>
              )}
              
              <IconButton onClick={handleDownload} sx={{ color: 'white' }}>
                <DownloadIcon />
              </IconButton>
              
              <IconButton onClick={toggleFullscreen} sx={{ color: 'white' }}>
                {isFullscreen ? <FullscreenExitIcon /> : <FullscreenIcon />}
              </IconButton>
              
              <IconButton onClick={onClose} sx={{ color: 'white' }}>
                <CloseIcon />
              </IconButton>
            </Box>
          </Box>
        </Fade>

        {/* Grid view */}
        {showGrid ? (
          <Fade in={showGrid}>
            <Box
              sx={{
                flex: 1,
                overflow: 'auto',
                p: 2,
              }}
            >
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6" color="white">
                  All Images ({images.length})
                </Typography>
                <IconButton onClick={() => setShowGrid(false)} sx={{ color: 'white' }}>
                  <CloseIcon />
                </IconButton>
              </Box>
              <ImageList cols={isMobile ? 2 : 4} gap={8}>
                {images.map((img, index) => (
                  <ImageListItem
                    key={img.id}
                    onClick={() => handleGridSelect(index)}
                    sx={{
                      cursor: 'pointer',
                      border: index === currentIndex ? `2px solid ${theme.palette.primary.main}` : 'none',
                      borderRadius: 1,
                      overflow: 'hidden',
                      '&:hover': {
                        opacity: 0.8,
                      },
                    }}
                  >
                    <img
                      src={img.thumbnailUrl || img.url}
                      alt={img.filename}
                      loading="lazy"
                      style={{
                        height: 150,
                        objectFit: 'cover',
                      }}
                    />
                  </ImageListItem>
                ))}
              </ImageList>
            </Box>
          </Fade>
        ) : (
          /* Main image view */
          <Box
            sx={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              position: 'relative',
              cursor: zoom > 1 ? (isDragging ? 'grabbing' : 'grab') : 'default',
            }}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          >
            {/* Navigation buttons */}
            {images.length > 1 && (
              <>
                <IconButton
                  onClick={(e) => {
                    e.stopPropagation();
                    handlePrev();
                  }}
                  sx={{
                    position: 'absolute',
                    left: 16,
                    bgcolor: 'rgba(0,0,0,0.5)',
                    color: 'white',
                    '&:hover': { bgcolor: 'rgba(0,0,0,0.7)' },
                    zIndex: 5,
                  }}
                >
                  <PrevIcon fontSize="large" />
                </IconButton>
                <IconButton
                  onClick={(e) => {
                    e.stopPropagation();
                    handleNext();
                  }}
                  sx={{
                    position: 'absolute',
                    right: 16,
                    bgcolor: 'rgba(0,0,0,0.5)',
                    color: 'white',
                    '&:hover': { bgcolor: 'rgba(0,0,0,0.7)' },
                    zIndex: 5,
                  }}
                >
                  <NextIcon fontSize="large" />
                </IconButton>
              </>
            )}

            {/* Image */}
            <Zoom in={true} key={currentIndex}>
              <img
                src={currentImage.url}
                alt={currentImage.filename}
                style={{
                  maxWidth: '100%',
                  maxHeight: '100%',
                  objectFit: 'contain',
                  transform: `scale(${zoom}) translate(${position.x / zoom}px, ${position.y / zoom}px)`,
                  transition: isDragging ? 'none' : 'transform 0.2s ease-out',
                }}
                draggable={false}
              />
            </Zoom>
          </Box>
        )}

        {/* Thumbnail strip at bottom */}
        {!showGrid && images.length > 1 && (
          <Fade in={!showGrid}>
            <Paper
              sx={{
                position: 'absolute',
                bottom: 0,
                left: 0,
                right: 0,
                bgcolor: 'rgba(0,0,0,0.8)',
                p: 1,
                display: 'flex',
                justifyContent: 'center',
                gap: 1,
                overflowX: 'auto',
              }}
            >
              {images.map((img, index) => (
                <Box
                  key={img.id}
                  onClick={() => handleGridSelect(index)}
                  sx={{
                    width: 60,
                    height: 60,
                    flexShrink: 0,
                    borderRadius: 1,
                    overflow: 'hidden',
                    cursor: 'pointer',
                    border: index === currentIndex ? `2px solid ${theme.palette.primary.main}` : '2px solid transparent',
                    opacity: index === currentIndex ? 1 : 0.6,
                    transition: 'all 0.2s',
                    '&:hover': {
                      opacity: 1,
                    },
                  }}
                >
                  <img
                    src={img.thumbnailUrl || img.url}
                    alt={img.filename}
                    style={{
                      width: '100%',
                      height: '100%',
                      objectFit: 'cover',
                    }}
                  />
                </Box>
              ))}
            </Paper>
          </Fade>
        )}
      </DialogContent>
    </Dialog>
  );
}

export default ImageGallery;
