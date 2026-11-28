import React, { createContext, useCallback, useContext, useRef, useState } from 'react';
import { Button, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle } from '@mui/material';

export interface ConfirmOptions {
  title: string;
  content?: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn | null>(null);

// 全局确认弹窗，替代浏览器原生 window.confirm，用法：const confirm = useConfirm(); if (!(await confirm({...}))) return;
export const ConfirmProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [options, setOptions] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<((ok: boolean) => void) | null>(null);

  const confirm = useCallback<ConfirmFn>((opts) => {
    resolver.current?.(false);
    setOptions(opts);
    return new Promise<boolean>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const settle = (ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOptions(null);
  };

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Dialog open={Boolean(options)} onClose={() => settle(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{options?.title}</DialogTitle>
        {options?.content && (
          <DialogContent>
            {typeof options.content === 'string' ? (
              <DialogContentText>{options.content}</DialogContentText>
            ) : (
              options.content
            )}
          </DialogContent>
        )}
        <DialogActions>
          <Button onClick={() => settle(false)}>{options?.cancelText || '取消'}</Button>
          <Button
            variant="contained"
            color={options?.danger ? 'error' : 'primary'}
            onClick={() => settle(true)}
            autoFocus
          >
            {options?.confirmText || '确定'}
          </Button>
        </DialogActions>
      </Dialog>
    </ConfirmContext.Provider>
  );
};

export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext);
  if (!ctx) {
    throw new Error('useConfirm 必须在 ConfirmProvider 内使用');
  }
  return ctx;
}
