export const KERNEL_PREFIXES = [
  'scsi_', 'kworker', 'rcu', 'migration', 'cpuhp', 'jbd2', 'ext4', 'watchdog', 'card', 'irq/'
];

export const SYSTEM_NAMES = [
  'systemd', 'kthreadd', 'swapper', 'lightdm', 'xorg', 'xfce4-session', 'xfce4-panel', 'thunar', 'dbus-daemon', 'xfwm4', 'pulseaudio'
];

export function isKernelOrSystem(proc) {
  if (!proc) return false;
  const pid = Number(proc.pid);
  if (!isNaN(pid) && pid <= 2) return true;
  const name = String(proc.name || proc.process_name || '').toLowerCase();
  if (!name) return false;
  if (KERNEL_PREFIXES.some(prefix => name.startsWith(prefix))) return true;
  if (SYSTEM_NAMES.some(sys => name.includes(sys))) return true;
  return false;
}

