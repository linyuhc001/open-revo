import React, { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Loader2, AlertCircle, RefreshCw, ExternalLink } from 'lucide-react';

interface BatteryHealthViewProps {
  onNavigateToOverview?: () => void;
}

/**
 * BatteryHealthView - Loads the battery-health Webview2 plugin content
 * and manages the sidecar service lifecycle.
 */
export const BatteryHealthView: React.FC<BatteryHealthViewProps> = ({ onNavigateToOverview }) => {
  const [htmlContent, setHtmlContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [serviceRunning, setServiceRunning] = useState<boolean | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);

  // Load the plugin HTML from the plugins directory
  const loadPluginHtml = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Try to load from Tauri's plugin system first
      const html = await invoke<string>('load_plugin_html', {
        pluginId: 'battery-health',
        surface: 'tab',
      });
      setHtmlContent(html);
      setServiceRunning(true);
    } catch (err: any) {
      console.warn('[BatteryHealthView] load_plugin_html failed, trying direct path:', err);
      // Fallback: try to read the HTML file directly
      try {
        const html = await invoke<string>('read_plugin_file', {
          pluginId: 'battery-health',
          path: 'index.html',
        });
        setHtmlContent(html);
        setServiceRunning(true);
      } catch (err2: any) {
        console.error('[BatteryHealthView] Failed to load plugin HTML:', err2);
        setError(
          typeof err2 === 'string'
            ? err2
            : err2?.message || '无法加载电池健康插件，请确认插件已正确安装'
        );
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // Check sidecar service status
  const checkServiceStatus = useCallback(async () => {
    try {
      const status = await invoke<string>('get_plugin_service_status', {
        pluginId: 'battery-health',
      });
      setServiceRunning(status.includes('running') || status.includes('active'));
    } catch {
      setServiceRunning(false);
    }
  }, []);

  // Start sidecar service
  const startService = useCallback(async () => {
    try {
      await invoke('start_plugin_service', { pluginId: 'battery-health' });
      setServiceRunning(true);
      setTimeout(checkServiceStatus, 2000);
    } catch (err: any) {
      console.error('[BatteryHealthView] Failed to start service:', err);
    }
  }, [checkServiceStatus]);

  // Initial load
  useEffect(() => {
    loadPluginHtml();
    checkServiceStatus();
  }, [loadPluginHtml, checkServiceStatus]);

  // Inject OpenRevo bridge into HTML content
  const preparedHtml = React.useMemo(() => {
    if (!htmlContent) return '';
    const bridgeScript = `
<script>
(function() {
  window.__OPENREVO_PLUGIN_ID__ = "battery-health";
  window.OpenRevo = {
    invoke: function() { return Promise.reject("Bridge unavailable"); },
    listen: function() { return Promise.resolve(function() {}); },
    emit: function() { return Promise.resolve(); },
    pluginId: "battery-health"
  };
})();
</script>
`;
    if (htmlContent.includes('<head>')) {
      return htmlContent.replace('<head>', `<head>${bridgeScript}`);
    } else if (htmlContent.includes('<html>')) {
      return htmlContent.replace('<html>', `<html><head>${bridgeScript}</head>`);
    } else {
      return `${bridgeScript}${htmlContent}`;
    }
  }, [htmlContent]);

  if (loading) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        height: '100%', gap: '12px', color: '#94a3b8'
      }}>
        <Loader2 size={28} className="animate-spin" style={{ animation: 'spin 1s linear infinite' }} />
        <span style={{ fontSize: '13px' }}>正在加载电池健康看板...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        height: '100%', gap: '12px', padding: '24px', textAlign: 'center'
      }}>
        <AlertCircle size={32} style={{ color: '#ef4444' }} />
        <span style={{ fontSize: '14px', color: '#cbd5e1' }}>{error}</span>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={loadPluginHtml}
            style={{
              padding: '6px 14px', fontSize: '12px', borderRadius: '6px',
              border: '1px solid rgba(255,255,255,0.16)', background: 'rgba(255,255,255,0.06)',
              color: '#f8fafc', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px'
            }}
          >
            <RefreshCw size={12} /> 重试加载
          </button>
          {!serviceRunning && (
            <button
              onClick={startService}
              style={{
                padding: '6px 14px', fontSize: '12px', borderRadius: '6px',
                border: '1px solid rgba(16,185,129,0.4)', background: 'rgba(16,185,129,0.15)',
                color: '#10b981', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px'
              }}
            >
              启动后台服务
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <iframe
      ref={iframeRef}
      srcDoc={preparedHtml}
      style={{
        width: '100%',
        height: '100%',
        border: 'none',
        background: '#0b0f17',
      }}
      sandbox="allow-scripts allow-same-origin allow-popups"
      title="电池健康看板"
    />
  );
};
