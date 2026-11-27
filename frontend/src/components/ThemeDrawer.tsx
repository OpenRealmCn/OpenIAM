import React from 'react';
import {
  alpha,
  Box,
  Button,
  Divider,
  Drawer,
  IconButton,
  Slider,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
  useTheme,
} from '@mui/material';
import {
  Check as CheckIcon,
  Close as CloseIcon,
  DarkMode as DarkIcon,
  LightMode as LightIcon,
  RestartAlt as ResetIcon,
  SettingsBrightness as SystemIcon,
} from '@mui/icons-material';
import {
  ColorModeSetting,
  MotionSpeed,
  THEME_PRESETS,
  useThemeStore,
} from '../store/themeStore';

interface ThemeDrawerProps {
  open: boolean;
  onClose: () => void;
}

export const ThemeDrawer: React.FC<ThemeDrawerProps> = ({ open, onClose }) => {
  const theme = useTheme();
  const {
    colorMode,
    preset,
    customColor,
    borderRadius,
    motionSpeed,
    setColorMode,
    setPreset,
    setCustomColor,
    setBorderRadius,
    setMotionSpeed,
    resetDefaults,
  } = useThemeStore();

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width: { xs: 310, sm: 340 },
          p: 2.5,
          borderLeft: 1,
          borderColor: 'divider',
        },
      }}
    >
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1.5}>
        <Typography variant="h6">外观设置</Typography>
        <IconButton size="small" onClick={onClose}>
          <CloseIcon fontSize="small" />
        </IconButton>
      </Stack>
      <Divider sx={{ mb: 2.5 }} />

      <Stack spacing={3} sx={{ flex: 1, overflowY: 'auto', pr: 0.5 }}>
        {/* 颜色模式 */}
        <Box>
          <Typography variant="subtitle2" mb={1.2}>
            颜色模式
          </Typography>
          <ToggleButtonGroup
            exclusive
            fullWidth
            size="small"
            value={colorMode}
            onChange={(_, v: ColorModeSetting | null) => v && setColorMode(v)}
          >
            <ToggleButton value="light">
              <LightIcon fontSize="small" sx={{ mr: 0.6 }} />
              浅色
            </ToggleButton>
            <ToggleButton value="dark">
              <DarkIcon fontSize="small" sx={{ mr: 0.6 }} />
              深色
            </ToggleButton>
            <ToggleButton value="system">
              <SystemIcon fontSize="small" sx={{ mr: 0.6 }} />
              跟随系统
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>

        {/* 主题色 */}
        <Box>
          <Typography variant="subtitle2" mb={1.2}>
            主题色
          </Typography>
          <Stack direction="row" spacing={1.2} flexWrap="wrap" useFlexGap mb={1.8}>
            {THEME_PRESETS.map((p) => {
              const active = preset === p.key;
              const swatch = theme.palette.mode === 'dark' ? p.darkMain : p.lightMain;
              return (
                <Tooltip key={p.key} title={p.label}>
                  <IconButton
                    size="small"
                    onClick={() => setPreset(p.key)}
                    sx={{
                      width: 34,
                      height: 34,
                      bgcolor: swatch,
                      color: '#fff',
                      outline: active ? `2px solid ${alpha(swatch, 0.45)}` : 'none',
                      outlineOffset: 2,
                      '&:hover': { bgcolor: swatch, opacity: 0.9 },
                    }}
                  >
                    {active && <CheckIcon sx={{ fontSize: 18 }} />}
                  </IconButton>
                </Tooltip>
              );
            })}
          </Stack>

          <Stack direction="row" spacing={1.2} alignItems="center">
            <Box
              component="input"
              type="color"
              value={customColor}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) => setCustomColor(e.target.value)}
              sx={{
                width: 38,
                height: 36,
                p: 0.3,
                border: 1,
                borderColor: 'divider',
                borderRadius: 1,
                bgcolor: 'transparent',
                cursor: 'pointer',
              }}
            />
            <TextField
              size="small"
              label="自定义色值"
              value={customColor}
              onChange={(e) => setCustomColor(e.target.value)}
              fullWidth
            />
          </Stack>
        </Box>

        {/* 圆角调节 */}
        <Box>
          <Stack direction="row" justifyContent="space-between" alignItems="center" mb={0.5}>
            <Typography variant="subtitle2">圆角大小</Typography>
            <Typography variant="caption" color="primary.main" fontWeight={700}>
              {borderRadius} px
            </Typography>
          </Stack>
          <Slider
            value={borderRadius}
            min={0}
            max={20}
            step={1}
            marks={[
              { value: 0, label: '0' },
              { value: 7, label: '默认' },
              { value: 14, label: '14' },
              { value: 20, label: '20' },
            ]}
            onChange={(_, v) => setBorderRadius(v as number)}
          />
        </Box>

        {/* 动画速度 */}
        <Box>
          <Typography variant="subtitle2" mb={1.2}>
            动画速度
          </Typography>
          <ToggleButtonGroup
            exclusive
            fullWidth
            size="small"
            value={motionSpeed}
            onChange={(_, v: MotionSpeed | null) => v && setMotionSpeed(v)}
          >
            <ToggleButton value="off">关闭</ToggleButton>
            <ToggleButton value="fast">极速</ToggleButton>
            <ToggleButton value="normal">标准</ToggleButton>
            <ToggleButton value="slow">舒缓</ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Stack>

      <Divider sx={{ my: 2 }} />
      <Button fullWidth variant="outlined" startIcon={<ResetIcon />} onClick={resetDefaults}>
        恢复默认外观
      </Button>
    </Drawer>
  );
};
