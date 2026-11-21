import assert from 'node:assert/strict';
import { test } from 'node:test';
import { certName, diffSys, judgeSys, parseRule, sysItems, sysMessage, type CertRow, type SysItem, type SysSnap } from './sys-watch.js';

const cert = (subject: string, store: CertRow['store'] = 'machine', thumb = 'AA11'): CertRow => ({ thumb, subject, store, until: '2035-01-01' });
const certItem = (c: CertRow): SysItem => sysItems({ certs: [c], certsOk: true }).items[0];
const rule = (raw: string): SysItem => sysItems({ firewall: [{ id: 'x', src: 'local', raw }], firewallOk: true }).items[0];

test('root certificates: unknown → high, tools → medium, antivirus / known CA / Windows list → low', () => {
  assert.equal(certName({ subject: 'CN=Evil Root CA, O=Nobody, C=XX' }), 'Evil Root CA');
  assert.equal(certName({ subject: 'OU=Copyright (c) 1997 Microsoft Corp., O=Microsoft Trust Network' }), 'Copyright (c) 1997 Microsoft Corp.');
  assert.equal(judgeSys(certItem(cert('CN=Evil Root CA, O=Nobody'))).severity, 'high');
  assert.equal(judgeSys(certItem(cert('CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST'))).reason, 'cert_tool');
  assert.equal(judgeSys(certItem(cert('CN=Blizzard Battle.net Local Cert'))).severity, 'medium');
  assert.equal(judgeSys(certItem(cert('CN=Avast Web/Mail Shield Root'))).severity, 'low');
  assert.equal(judgeSys(certItem(cert('CN=DigiCert Global Root G2, O=DigiCert Inc'))).severity, 'low');
  assert.equal(judgeSys(certItem(cert('CN=DigiCert Global Root G2, O=DigiCert Inc', 'user'))).severity, 'high', 'a known name in the user store is not trusted on its name');
  assert.equal(judgeSys(certItem(cert('CN=Some Unknown Gov Root', 'authroot'))).reason, 'cert_windows');
});

test('firewall rules: parsed and judged by program, ports and reach', () => {
  const temp = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\\Users\\me\\AppData\\Local\\Temp\\x\\svc.exe|Name=Updater|');
  assert.equal(temp.name, 'Updater');
  assert.equal(judgeSys(temp, { state: 'signed', signer: 'X' }).reason, 'fw_temp', 'temp folder is high even when signed');

  const any = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|Name=Open all|');
  assert.deepEqual([judgeSys(any).severity, judgeSys(any).reason], ['high', 'fw_any_program']);

  const rdp = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=Port 3389|');
  assert.equal(judgeSys(rdp).reason, 'fw_remote_port');
  assert.equal(judgeSys(rdp).severity, 'high');
  const lan = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|RA4=LocalSubnet|Name=RDP LAN|');
  assert.equal(judgeSys(lan).severity, 'medium', 'home network only is capped');
  const ts = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|Profile=Domain|Profile=Private|LA4=100.64.0.20|Name=Tailscale-In|');
  assert.equal(judgeSys(ts).severity, 'medium', 'one adapter only is capped');
  assert.match(ts.value, /one network adapter only/);

  const mysql = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3306|Name=Port 3306|');
  assert.equal(judgeSys(mysql).severity, 'medium');

  const game = rule('v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=D:\\Games\\x\\game.exe|Name=game|');
  assert.equal(judgeSys(game, { state: 'signed', signer: 'Valve' }).severity, 'low');
  assert.equal(judgeSys(game, { state: 'unsigned' }).severity, 'medium');
  assert.equal(judgeSys(game, { state: 'invalid' }).severity, 'high');
  assert.equal(judgeSys(game, { state: 'missing' }).reason, 'fw_missing');

  const builtin = rule('v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=5357|RA4=LocalSubnet|App=System|Name=@FirewallAPI.dll,-32817|');
  assert.equal(builtin.name, 'Windows built-in rule');
  assert.equal(judgeSys(builtin).severity, 'low');
  const smb = parseRule('v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=445|App=System|Name=@FirewallAPI.dll,-28502|', 'local');
  assert.equal(smb.builtin, true);
  assert.equal(smb.protocol, 'TCP');
});

test('settings: risky switches become items; Guest / Administrator by well-known SID', () => {
  const { items } = sysItems({ settings: { rdp: true, rdpNla: false, lsaPpl: false, wdigest: false, smb1: null, users: [{ name: 'Gast', sid: 'S-1-5-21-1-2-3-501' }, { name: 'me', sid: 'S-1-5-21-1-2-3-1001' }] }, settingsOk: true });
  assert.deepEqual(items.map((i) => i.setting), ['rdp', 'rdp_no_nla', 'lsa_off', 'guest']);
  assert.equal(judgeSys(items[0]).severity, 'high');
  assert.equal(judgeSys(items[2]).severity, 'medium');
  const m = sysMessage(items[3], judgeSys(items[3]), 'This PC');
  assert.match(m.th, /net user Guest \/active:no/);
});

test('diff: first run silent, new / removed reported, unreadable sections kept', () => {
  const s1: SysSnap = { certs: [cert('CN=A', 'machine', 'T1')], certsOk: true, firewall: [], firewallOk: true, settings: { rdp: false }, settingsOk: true };
  const first = diffSys(s1, null);
  assert.equal(first.changes.length, 0);
  const s2: SysSnap = { certs: [cert('CN=A', 'machine', 'T1'), cert('CN=Evil', 'user', 'T2')], certsOk: true, firewall: [], firewallOk: true, settings: { rdp: true }, settingsOk: true };
  const second = diffSys(s2, first.next);
  assert.deepEqual(second.changes.map((c) => c.kind === 'added' ? c.item.name : c.name), ['Evil', 'Remote Desktop is on']);
  // Certificates unreadable this time: no "removed" for them, and they stay in the baseline.
  const third = diffSys({ certs: null, certsOk: false, firewall: [], firewallOk: true, settings: { rdp: false }, settingsOk: true }, second.next);
  assert.deepEqual(third.changes.map((c) => (c.kind === 'removed' ? c.name : 'added')), ['Remote Desktop is on']);
  assert.ok(third.next.items.includes('cert|user|T2'));
});
