import assert from 'node:assert/strict';
import { test } from 'node:test';
import { diffPeriph, judgePeriph, periphItems, periphMessage, wifiRisk, type PeriphChange, type PeriphItem, type PeriphSnap } from './periph-watch.js';

const itemOf = (c: PeriphChange): PeriphItem => {
  if (c.kind !== 'added') throw new Error('expected an added item');
  return c.item;
};

const base: PeriphSnap = {
  disks: [{ id: 'SCSI\\DISK&VEN_NVME&PROD_WD_BLACK\\5&1', name: 'WD_BLACK SN770 1TB', present: true }],
  disksOk: true,
  keyboards: [
    { id: 'HID\\VID_046D&PID_C232\\2&357F35A&0&0000', name: 'HID Keyboard Device', present: true },
    { id: 'ACPI\\HPQ8001\\4&34FF65F&0', name: 'Standard PS/2 Keyboard', present: true },
  ],
  keyboardsOk: true,
  wifi: [{ ssid: 'Home_5G', auth: 'WPA3SAE', enc: 'AES', mode: 'auto' }, { ssid: 'Cafe', auth: 'open', enc: 'none', mode: 'manual' }],
  wifiOk: true,
  wifiNow: 'Home_5G',
};

test('items: one keyboard per product (another USB port is not a new device), vendor names', () => {
  const moved: PeriphSnap = { ...base, keyboards: [...base.keyboards!, { id: 'HID\\VID_046D&PID_C232\\9&AAAA&0&0000', name: 'HID Keyboard Device' }] };
  const kb = periphItems(moved).items.filter((i) => i.section === 'keyboard');
  assert.equal(kb.length, 2);
  assert.equal(kb[0].name, 'Logitech (VID 046D PID C232)');
  assert.equal(wifiRisk('open', 'none'), 'open');
  assert.equal(wifiRisk('OWE', 'AES'), 'ok', 'Enhanced Open encrypts');
  assert.equal(wifiRisk('open', 'WEP'), 'weak');
});

test('judging: USB drive medium, dev-board keyboard high, keyboard + new drive high, plain keyboard low', () => {
  const after: PeriphSnap = {
    ...base,
    disks: [...base.disks!, { id: 'USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA\\4C53000', name: 'SanDisk Ultra USB Device' }],
    keyboards: [...base.keyboards!, { id: 'HID\\VID_2E8A&PID_000A&MI_00\\8&1', name: 'HID Keyboard Device' }, { id: 'HID\\VID_1532&PID_0084\\8&2', name: 'HID Keyboard Device' }],
  };
  const { changes } = diffPeriph(after, diffPeriph(base, null).next);
  const added = changes.flatMap((c) => (c.kind === 'added' ? [c.item] : []));
  assert.deepEqual(added.map((i) => i.section), ['disk', 'keyboard', 'keyboard']);
  assert.deepEqual(judgePeriph(added[0]), { severity: 'medium', reason: 'usb_drive', detail: 'SanDisk Ultra USB Device — a USB drive this PC has never seen was plugged in' });
  assert.equal(judgePeriph(added[1]).reason, 'keyboard_devboard', 'Raspberry Pi Pico "keyboard"');
  assert.equal(judgePeriph(added[2]).severity, 'low', 'a Razer keyboard alone is fine');
  assert.equal(judgePeriph(added[2], { newDrive: true }).reason, 'keyboard_with_drive');
  assert.match(periphMessage(added[1], judgePeriph(added[1]), 'PC').th, /BadUSB/);
});

test('Wi-Fi: new open auto-connect saved → medium; being on an open Wi-Fi is reported even at the first run and resolves on leaving', () => {
  const first = diffPeriph({ ...base, wifiNow: 'Cafe' }, null);
  assert.deepEqual(first.changes.map((c) => (c.kind === 'added' ? `${c.item.section}:${c.item.name}` : 'x')), ['wifinow:Cafe']);
  assert.equal(judgePeriph(itemOf(first.changes[0])).severity, 'medium');
  const left = diffPeriph({ ...base, wifiNow: '' }, first.next);
  assert.deepEqual(left.changes.map((c) => c.kind), ['removed']);

  const saved = diffPeriph({ ...base, wifi: [...base.wifi!, { ssid: 'Free WiFi', auth: 'open', enc: 'none', mode: 'auto' }] }, left.next);
  const it = itemOf(saved.changes[0]);
  assert.equal(judgePeriph(it).reason, 'wifi_open_auto');
});

test('diff: unreadable sections keep their items and report nothing', () => {
  const b = diffPeriph(base, null).next;
  const r = diffPeriph({ ...base, disks: null, disksOk: false, keyboards: [], keyboardsOk: true }, b);
  assert.ok(r.changes.every((c) => c.kind === 'removed' && c.key.startsWith('kbd|')), 'only keyboards (readable, now empty) are removed');
  assert.ok(r.next.items.some((k) => k.startsWith('disk|')), 'disks kept while unreadable');
});
