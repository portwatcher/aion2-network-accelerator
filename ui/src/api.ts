import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import { check } from '@tauri-apps/plugin-updater';

export interface ProxyStatus {
  state: 'disconnected' | 'connecting' | 'connected';
  rtt_ms: number | null;
  uptime_secs: number;
  bytes_tx: number;
  bytes_rx: number;
  active_connections: number;
}

export interface LogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error';
  message: string;
}

export interface RelayConfig {
  relay_addr: string;
  key_hex: string;
}

export interface DeployConfig {
  host: string;
  port?: number;
  user: string;
  password: string;
}

export interface DeployResult {
  key_hex: string;
  relay_addr: string;
}

export interface Profile {
  name: string;
  relay_addr: string;
  key_hex: string;
  vps_host?: string;
  ssh_port?: number;
  ssh_user?: string;
}

export async function startProxy(config: RelayConfig): Promise<void> {
  return invoke('start_proxy', { config });
}

export async function stopProxy(): Promise<void> {
  return invoke('stop_proxy');
}

export async function getStatus(): Promise<ProxyStatus> {
  return invoke('get_status');
}

export async function deployRelay(config: DeployConfig): Promise<DeployResult> {
  return invoke('deploy_relay', { config });
}

// Profile management
export async function saveProfile(profile: Profile): Promise<void> {
  return invoke('save_profile', { profile });
}

export async function loadProfiles(): Promise<[Profile[], string | null]> {
  return invoke('load_profiles');
}

export async function deleteProfile(name: string): Promise<void> {
  return invoke('delete_profile', { name });
}

export async function setActiveProfile(name: string): Promise<void> {
  return invoke('set_active_profile', { name });
}

// Updater
export async function checkForUpdates(): Promise<{ available: boolean; version?: string }> {
  try {
    const update = await check();
    if (update) {
      return { available: true, version: update.version };
    }
    return { available: false };
  } catch {
    return { available: false };
  }
}

export function onStatusUpdate(callback: (status: ProxyStatus) => void): Promise<UnlistenFn> {
  return listen<ProxyStatus>('proxy-status', (event) => {
    callback(event.payload);
  });
}

export function onLogEntry(callback: (entry: LogEntry) => void): Promise<UnlistenFn> {
  return listen<LogEntry>('proxy-log', (event) => {
    callback(event.payload);
  });
}

export function onDeployProgress(callback: (msg: string) => void): Promise<UnlistenFn> {
  return listen<string>('deploy-progress', (event) => {
    callback(event.payload);
  });
}
