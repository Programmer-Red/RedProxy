import { describe, expect, it } from 'vitest';
import { buildShareLink, buildXrayConfig, parseShareLink } from '../server/src/xray';
import type { NodeRecord } from '../server/src/types';

describe('xray share links', () => {
  it('parses vless links', () => {
    const parsed = parseShareLink(
      'vless://11111111-1111-1111-1111-111111111111@remote.example.com:443?encryption=none&security=tls&sni=remote.example.com&type=ws&host=remote.example.com&path=%2Fws&flow=xtls-rprx-vision#Tokyo',
    );
    expect(parsed).not.toBeNull();
    expect(parsed!.kind).toBe('xray');
    expect(parsed!.name).toBe('Tokyo');
    expect(parsed!.host).toBe('remote.example.com');
    expect(parsed!.port).toBe(443);
    expect(parsed!.xray?.protocol).toBe('vless');
    expect(parsed!.xray?.uuid).toBe('11111111-1111-1111-1111-111111111111');
    expect(parsed!.xray?.network).toBe('ws');
    expect(parsed!.xray?.security).toBe('tls');
    expect(parsed!.xray?.path).toBe('/ws');
  });

  it('parses trojan and shadowsocks links', () => {
    const trojan = parseShareLink('trojan://secret@remote.example.com:443?sni=remote.example.com&type=grpc&serviceName=grpc-svc#Trojan');
    expect(trojan?.xray?.protocol).toBe('trojan');
    expect(trojan?.xray?.password).toBe('secret');
    expect(trojan?.xray?.network).toBe('grpc');

    const ss = parseShareLink('ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@remote.example.com:8388#SS');
    expect(ss?.xray?.protocol).toBe('shadowsocks');
    expect(ss?.xray?.method).toBe('aes-256-gcm');
    expect(ss?.xray?.password).toBe('password');
  });

  it('parses vmess links and traditional proxy links', () => {
    const vmessJson = { v: '2', ps: 'VMess Tokyo', add: 'remote.example.com', port: '443', id: '11111111-1111-1111-1111-111111111111', aid: '0', net: 'ws', path: '/vm', tls: 'tls', sni: 'remote.example.com' };
    const vmess = parseShareLink(`vmess://${Buffer.from(JSON.stringify(vmessJson)).toString('base64')}`);
    expect(vmess?.xray?.protocol).toBe('vmess');
    expect(vmess?.name).toBe('VMess Tokyo');

    const socks = parseShareLink('socks5://user:pass@127.0.0.1:1080#Local');
    expect(socks?.kind).toBe('proxy');
    expect(socks?.scheme).toBe('socks5');
    expect(socks?.username).toBe('user');
    expect(socks?.password).toBe('pass');
  });

  it('builds an Xray config with a local inbound and a vless outbound', () => {
    const node: NodeRecord = {
      id: 'xray-1',
      name: 'Xray Tokyo',
      kind: 'xray',
      scheme: 'socks5',
      host: 'remote.example.com',
      port: 443,
      username: null,
      password: null,
      enabled: true,
      createdAt: Date.now(),
      xray: {
        protocol: 'vless',
        uuid: '11111111-1111-1111-1111-111111111111',
        network: 'ws',
        security: 'tls',
        sni: 'remote.example.com',
        path: '/ws',
      },
      localScheme: 'socks5',
      localHost: '127.0.0.1',
      localPort: 10808,
    };
    const config = buildXrayConfig(node) as {
      inbounds: Array<{ port: number; protocol: string; listen: string }>;
      outbounds: Array<{ protocol: string; settings?: { vnext?: Array<{ address: string }> } }>;
    };
    expect(config.inbounds[0]).toMatchObject({ port: 10808, protocol: 'socks', listen: '127.0.0.1' });
    expect(config.outbounds[0]?.protocol).toBe('vless');
    expect(config.outbounds[0]?.settings?.vnext?.[0]?.address).toBe('remote.example.com');

    const link = buildShareLink(node);
    expect(link?.startsWith('vless://')).toBe(true);
  });
});
