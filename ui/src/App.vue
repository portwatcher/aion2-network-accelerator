<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick, computed } from 'vue';
import {
  ProxyStatus,
  LogEntry,
  Profile,
  RelayConfig,
  DeployConfig,
  DeployResult,
  startProxy,
  stopProxy,
  getStatus,
  deployRelay,
  saveProfile,
  loadProfiles,
  deleteProfile,
  setActiveProfile,
  checkForUpdates,
  onStatusUpdate,
  onLogEntry,
  onDeployProgress,
} from './api';

const DEFAULT_STATUS: ProxyStatus = {
  state: 'disconnected',
  rtt_ms: null,
  uptime_secs: 0,
  bytes_tx: 0,
  bytes_rx: 0,
  active_connections: 0,
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

function rttClass(rtt: number | null): string {
  if (rtt === null) return '';
  if (rtt < 100) return 'good';
  if (rtt < 200) return 'medium';
  return 'bad';
}

const tab = ref<'proxy' | 'setup'>('proxy');
const status = ref<ProxyStatus>({ ...DEFAULT_STATUS });
const logs = ref<LogEntry[]>([]);
const showSettings = ref(true);
const relayAddr = ref('130.94.37.247:443');
const keyHex = ref('');
const loading = ref(false);
const logEl = ref<HTMLDivElement | null>(null);

// Setup Relay state
const vpsHost = ref('');
const sshPort = ref('22');
const sshUser = ref('root');
const sshPassword = ref('');
const deploying = ref(false);
const deployLogs = ref<string[]>([]);
const deployLogEl = ref<HTMLDivElement | null>(null);

// Connection profiles state
const profiles = ref<Profile[]>([]);
const activeProfileName = ref<string | null>(null);
const profileName = ref('');
const showProfileSave = ref(false);
const updateStatus = ref<string | null>(null);

const isRunning = computed(() => status.value.state === 'connected' || status.value.state === 'connecting');

function addLog(entry: LogEntry) {
  logs.value.push(entry);
  if (logs.value.length > 200) {
    logs.value = logs.value.slice(-200);
  }
}

// Auto-scroll logs
watch(logs, () => {
  nextTick(() => {
    if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight;
  });
}, { deep: true });

watch(deployLogs, () => {
  nextTick(() => {
    if (deployLogEl.value) deployLogEl.value.scrollTop = deployLogEl.value.scrollHeight;
  });
}, { deep: true });

// Event subscriptions
const unlisteners: Array<() => void> = [];
let pollInterval: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  // Subscribe to events
  unlisteners.push(await onStatusUpdate((s) => { status.value = s; }));
  unlisteners.push(await onLogEntry((e) => addLog(e)));
  unlisteners.push(await onDeployProgress((msg) => { deployLogs.value.push(msg); }));

  // Poll status every 2s as fallback
  pollInterval = setInterval(async () => {
    try {
      status.value = await getStatus();
    } catch {
      // Backend not ready yet
    }
  }, 2000);

  // Load saved settings from localStorage
  const savedKey = localStorage.getItem('aion2_key');
  if (savedKey) keyHex.value = savedKey;
  const savedAddr = localStorage.getItem('aion2_relay');
  if (savedAddr) relayAddr.value = savedAddr;
  const savedVps = localStorage.getItem('aion2_vps_host');
  if (savedVps) vpsHost.value = savedVps;
  const savedPort = localStorage.getItem('aion2_ssh_port');
  if (savedPort) sshPort.value = savedPort;
  const savedUser = localStorage.getItem('aion2_ssh_user');
  if (savedUser) sshUser.value = savedUser;

  // Load connection profiles
  try {
    const [profs, active] = await loadProfiles();
    profiles.value = profs;
    if (active) {
      activeProfileName.value = active;
      const prof = profs.find((p) => p.name === active);
      if (prof) {
        relayAddr.value = prof.relay_addr;
        keyHex.value = prof.key_hex;
        if (prof.vps_host) vpsHost.value = prof.vps_host;
        if (prof.ssh_port) sshPort.value = String(prof.ssh_port);
        if (prof.ssh_user) sshUser.value = prof.ssh_user;
      }
    }
  } catch {}
});

onUnmounted(() => {
  unlisteners.forEach((u) => u());
  if (pollInterval) clearInterval(pollInterval);
});

async function handleSelectProfile(name: string) {
  const prof = profiles.value.find((p) => p.name === name);
  if (!prof) return;
  activeProfileName.value = name;
  relayAddr.value = prof.relay_addr;
  keyHex.value = prof.key_hex;
  if (prof.vps_host) vpsHost.value = prof.vps_host;
  if (prof.ssh_port) sshPort.value = String(prof.ssh_port);
  if (prof.ssh_user) sshUser.value = prof.ssh_user;
  localStorage.setItem('aion2_key', prof.key_hex);
  localStorage.setItem('aion2_relay', prof.relay_addr);
  try { await setActiveProfile(name); } catch {}
}

async function handleSaveProfile() {
  const name = profileName.value.trim();
  if (!name) return;
  const prof: Profile = {
    name,
    relay_addr: relayAddr.value.trim(),
    key_hex: keyHex.value.trim(),
    vps_host: vpsHost.value.trim() || undefined,
    ssh_port: parseInt(sshPort.value) || undefined,
    ssh_user: sshUser.value.trim() || undefined,
  };
  try {
    await saveProfile(prof);
    const [profs] = await loadProfiles();
    profiles.value = profs;
    activeProfileName.value = name;
    showProfileSave.value = false;
    profileName.value = '';
    await setActiveProfile(name);
  } catch (e) {
    addLog({ timestamp: new Date().toISOString(), level: 'error', message: `Save profile: ${e}` });
  }
}

async function handleDeleteProfile(name: string) {
  try {
    await deleteProfile(name);
    const [profs, active] = await loadProfiles();
    profiles.value = profs;
    activeProfileName.value = active;
  } catch (e) {
    addLog({ timestamp: new Date().toISOString(), level: 'error', message: `Delete profile: ${e}` });
  }
}

async function handleCheckUpdates() {
  updateStatus.value = 'Checking...';
  const result = await checkForUpdates();
  if (result.available) {
    updateStatus.value = `Update available: v${result.version}`;
  } else {
    updateStatus.value = 'Up to date';
    setTimeout(() => { updateStatus.value = null; }, 3000);
  }
}

async function handleStart() {
  if (!keyHex.value.trim()) {
    addLog({ timestamp: new Date().toISOString(), level: 'error', message: 'Please enter a key' });
    return;
  }
  loading.value = true;
  try {
    localStorage.setItem('aion2_key', keyHex.value.trim());
    localStorage.setItem('aion2_relay', relayAddr.value.trim());
    const config: RelayConfig = {
      relay_addr: relayAddr.value.trim(),
      key_hex: keyHex.value.trim(),
    };
    await startProxy(config);
    showSettings.value = false;
    addLog({ timestamp: new Date().toISOString(), level: 'info', message: 'Proxy started' });
  } catch (e) {
    addLog({ timestamp: new Date().toISOString(), level: 'error', message: `Failed to start: ${e}` });
  } finally {
    loading.value = false;
  }
}

async function handleStop() {
  loading.value = true;
  try {
    await stopProxy();
    status.value = { ...DEFAULT_STATUS };
    addLog({ timestamp: new Date().toISOString(), level: 'info', message: 'Proxy stopped' });
  } catch (e) {
    addLog({ timestamp: new Date().toISOString(), level: 'error', message: `Failed to stop: ${e}` });
  } finally {
    loading.value = false;
  }
}

async function handleDeploy() {
  if (!vpsHost.value.trim() || !sshPassword.value.trim()) return;
  deploying.value = true;
  deployLogs.value = [];
  try {
    localStorage.setItem('aion2_vps_host', vpsHost.value.trim());
    localStorage.setItem('aion2_ssh_port', sshPort.value);
    localStorage.setItem('aion2_ssh_user', sshUser.value);

    const config: DeployConfig = {
      host: vpsHost.value.trim(),
      port: parseInt(sshPort.value) || 22,
      user: sshUser.value.trim() || 'root',
      password: sshPassword.value,
    };
    const result: DeployResult = await deployRelay(config);

    relayAddr.value = result.relay_addr;
    keyHex.value = result.key_hex;
    localStorage.setItem('aion2_relay', result.relay_addr);
    localStorage.setItem('aion2_key', result.key_hex);

    deployLogs.value.push('Done! Key auto-filled in Proxy tab.');
  } catch (e) {
    deployLogs.value.push(`ERROR: ${e}`);
  } finally {
    deploying.value = false;
  }
}

function onProfileSelect(event: Event) {
  const val = (event.target as HTMLSelectElement).value;
  if (val) handleSelectProfile(val);
}
</script>

<template>
  <div id="root">
    <div class="titlebar">
      <svg class="titlebar-icon" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="currentColor" stroke-width="2" fill="none" />
      </svg>
      Aion2 Proxy
      <span style="margin-left: auto; font-size: 11px">
        <span v-if="updateStatus" :style="{ color: updateStatus.startsWith('Update') ? 'var(--warning)' : 'var(--text-dim)' }">{{ updateStatus }}</span>
        <button v-else class="settings-toggle" @click="handleCheckUpdates" title="Check for updates">v0.1.0</button>
      </span>
    </div>

    <!-- Tab Bar -->
    <div class="tab-bar">
      <button :class="['tab', tab === 'proxy' && 'tab-active']" @click="tab = 'proxy'">Proxy</button>
      <button :class="['tab', tab === 'setup' && 'tab-active']" @click="tab = 'setup'">Setup Relay</button>
    </div>

    <div class="main">
      <!-- Proxy Tab -->
      <template v-if="tab === 'proxy'">
        <!-- Status Card -->
        <div class="card">
          <div class="card-header">
            <span class="card-title">Status</span>
            <div class="status-indicator">
              <span :class="['status-dot', status.state]" />
              <span>{{ status.state === 'connected' ? 'Connected' : status.state === 'connecting' ? 'Connecting...' : 'Disconnected' }}</span>
            </div>
          </div>
          <div class="stats">
            <div class="stat-box">
              <div :class="['stat-value', rttClass(status.rtt_ms)]">
                {{ status.rtt_ms !== null ? `${status.rtt_ms}` : '\u2014' }}
              </div>
              <div class="stat-label">Latency (ms)</div>
            </div>
            <div class="stat-box">
              <div class="stat-value">{{ status.active_connections }}</div>
              <div class="stat-label">Connections</div>
            </div>
            <div class="stat-box">
              <div class="stat-value">{{ formatBytes(status.bytes_tx) }}</div>
              <div class="stat-label">Sent</div>
            </div>
            <div class="stat-box">
              <div class="stat-value">{{ formatBytes(status.bytes_rx) }}</div>
              <div class="stat-label">Received</div>
            </div>
            <div class="stat-box">
              <div class="stat-value">{{ formatUptime(status.uptime_secs) }}</div>
              <div class="stat-label">Uptime</div>
            </div>
          </div>
        </div>

        <!-- Connection Settings -->
        <div class="card">
          <div class="card-header">
            <span class="card-title">Connection</span>
            <div style="display: flex; gap: 8px; align-items: center">
              <select
                v-if="profiles.length > 0"
                class="form-input"
                style="padding: 4px 8px; font-size: 12px; width: auto; min-width: 120px"
                :value="activeProfileName || ''"
                @change="onProfileSelect"
                :disabled="isRunning"
              >
                <option value="">Select profile...</option>
                <option v-for="p in profiles" :key="p.name" :value="p.name">{{ p.name }}</option>
              </select>
              <button v-if="isRunning" class="settings-toggle" @click="showSettings = !showSettings">
                {{ showSettings ? '\u25B2 Hide' : '\u25BC Show' }}
              </button>
            </div>
          </div>

          <div v-if="showSettings" style="display: flex; flex-direction: column; gap: 12px">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Relay Address</label>
                <input class="form-input" type="text" v-model="relayAddr" placeholder="ip:port" :disabled="isRunning" />
              </div>
              <div class="form-group">
                <label class="form-label">Key (hex)</label>
                <input class="form-input" type="password" v-model="keyHex" placeholder="64-character hex key" :disabled="isRunning" />
              </div>
            </div>

            <div class="actions">
              <button
                v-if="!isRunning"
                class="btn btn-primary btn-lg btn-block"
                @click="handleStart"
                :disabled="loading || !keyHex.trim()"
              >
                {{ loading ? 'Starting...' : '\u25B6 Start Proxy' }}
              </button>
              <button
                v-else
                class="btn btn-danger btn-lg btn-block"
                @click="handleStop"
                :disabled="loading"
              >
                {{ loading ? 'Stopping...' : '\u25A0 Stop Proxy' }}
              </button>
            </div>

            <!-- Profile save/delete row -->
            <div v-if="!isRunning" style="display: flex; gap: 8px; align-items: center">
              <template v-if="showProfileSave">
                <input
                  class="form-input"
                  type="text"
                  v-model="profileName"
                  placeholder="Profile name"
                  style="flex: 1; padding: 6px 10px; font-size: 13px"
                  @keydown.enter="handleSaveProfile"
                />
                <button class="btn btn-primary" style="padding: 6px 14px; font-size: 13px" @click="handleSaveProfile" :disabled="!profileName.trim()">Save</button>
                <button class="btn btn-secondary" style="padding: 6px 14px; font-size: 13px" @click="showProfileSave = false; profileName = ''">Cancel</button>
              </template>
              <template v-else>
                <button class="btn btn-secondary" style="padding: 6px 14px; font-size: 13px" @click="profileName = activeProfileName || ''; showProfileSave = true">Save Profile</button>
                <button
                  v-if="activeProfileName"
                  class="btn btn-secondary"
                  style="padding: 6px 14px; font-size: 13px; color: var(--error)"
                  @click="handleDeleteProfile(activeProfileName)"
                >Delete</button>
              </template>
            </div>
          </div>
        </div>

        <!-- Logs -->
        <div class="card" style="flex: 1; display: flex; flex-direction: column; min-height: 0">
          <div class="card-header">
            <span class="card-title">Logs</span>
            <button class="settings-toggle" @click="logs = []">Clear</button>
          </div>
          <div class="log-viewer" ref="logEl" style="flex: 1">
            <span v-if="logs.length === 0" class="log-line" style="color: var(--text-dim)">
              No logs yet. Start the proxy to see activity.
            </span>
            <span v-for="(entry, i) in logs" :key="i" class="log-line">
              <span class="log-time">{{ new Date(entry.timestamp).toLocaleTimeString() }} </span>
              <span :class="`log-${entry.level}`">{{ entry.message }}</span>
              {{ '\n' }}
            </span>
          </div>
        </div>
      </template>

      <!-- Setup Relay Tab -->
      <template v-else>
        <div class="card">
          <div class="card-header">
            <span class="card-title">Deploy Relay to VPS</span>
          </div>
          <div style="display: flex; flex-direction: column; gap: 12px">
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">VPS Host</label>
                <input class="form-input" type="text" v-model="vpsHost" placeholder="IP address" :disabled="deploying" />
              </div>
              <div class="form-group">
                <label class="form-label">SSH Port</label>
                <input class="form-input" type="text" v-model="sshPort" placeholder="22" :disabled="deploying" />
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">SSH User</label>
                <input class="form-input" type="text" v-model="sshUser" placeholder="root" :disabled="deploying" />
              </div>
              <div class="form-group">
                <label class="form-label">SSH Password</label>
                <input class="form-input" type="password" v-model="sshPassword" placeholder="Enter password" :disabled="deploying" />
              </div>
            </div>

            <p class="hint-text">
              Uploads the pre-compiled relay binary, sets up systemd, generates a tunnel key,
              and starts the service. The key will be auto-filled in the Proxy tab.
            </p>

            <button
              class="btn btn-primary btn-lg btn-block"
              @click="handleDeploy"
              :disabled="deploying || !vpsHost.trim() || !sshPassword.trim()"
            >
              {{ deploying ? 'Deploying...' : 'Deploy Relay' }}
            </button>
          </div>
        </div>

        <!-- Deploy Progress -->
        <div v-if="deployLogs.length > 0" class="card" style="flex: 1; display: flex; flex-direction: column; min-height: 0">
          <div class="card-header">
            <span class="card-title">Deploy Progress</span>
            <button class="settings-toggle" @click="deployLogs = []">Clear</button>
          </div>
          <div class="log-viewer" ref="deployLogEl" style="flex: 1">
            <span v-for="(msg, i) in deployLogs" :key="i" class="log-line">
              <span :class="msg.startsWith('ERROR') ? 'log-error' : 'log-info'">{{ msg }}</span>
              {{ '\n' }}
            </span>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>
