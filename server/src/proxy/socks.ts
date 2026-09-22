import net from 'node:net';

export interface UpstreamTarget {
  host: string;
  port: number;
}

/**
 * Perform a SOCKS4/SOCKS5 handshake on an already-connected socket.
 * Resolves once the socket is ready to carry raw application bytes.
 */
export function socksHandshake(
  socket: net.Socket,
  scheme: 'socks4' | 'socks5',
  target: UpstreamTarget,
  credentials: { username: string | null; password: string | null },
): Promise<void> {
  return scheme === 'socks5'
    ? socks5Handshake(socket, target, credentials)
    : socks4Handshake(socket, target, credentials);
}

function readExactly(socket: net.Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length >= length) {
        cleanup();
        resolve(buffer.subarray(0, length));
      }
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onClose = (): void => {
      cleanup();
      reject(new Error('socket closed during SOCKS handshake'));
    };
    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    };
    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
  });
}

async function socks5Handshake(
  socket: net.Socket,
  target: UpstreamTarget,
  credentials: { username: string | null; password: string | null },
): Promise<void> {
  const useAuth = Boolean(credentials.username);
  socket.write(useAuth ? Buffer.from([0x05, 0x02, 0x00, 0x02]) : Buffer.from([0x05, 0x01, 0x00]));

  const method = await readExactly(socket, 2);
  if (method[0] !== 0x05) throw new Error('SOCKS5: bad version');
  if (method[1] === 0xff) throw new Error('SOCKS5: no acceptable auth method');

  if (method[1] === 0x02) {
    const username = Buffer.from(credentials.username ?? '', 'utf8');
    const password = Buffer.from(credentials.password ?? '', 'utf8');
    const authRequest = Buffer.concat([
      Buffer.from([0x01, username.length]),
      username,
      Buffer.from([password.length]),
      password,
    ]);
    socket.write(authRequest);
    const authReply = await readExactly(socket, 2);
    if (authReply[1] !== 0x00) throw new Error('SOCKS5: authentication rejected');
  }

  const hostBuffer = Buffer.from(target.host, 'utf8');
  const portBuffer = Buffer.alloc(2);
  portBuffer.writeUInt16BE(target.port, 0);
  const connectRequest = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuffer.length]), hostBuffer, portBuffer]);
  socket.write(connectRequest);

  const reply = await readExactly(socket, 4);
  if (reply[0] !== 0x05 || reply[1] !== 0x00) {
    throw new Error(`SOCKS5: connect failed (code ${reply[1]})`);
  }
  const addressType = reply[3];
  if (addressType === 0x01) await readExactly(socket, 4 + 2);
  else if (addressType === 0x04) await readExactly(socket, 16 + 2);
  else if (addressType === 0x03) {
    const lengthBuffer = await readExactly(socket, 1);
    await readExactly(socket, lengthBuffer[0]! + 2);
  }
}

async function socks4Handshake(
  socket: net.Socket,
  target: UpstreamTarget,
  credentials: { username: string | null; password: string | null },
): Promise<void> {
  const userid = Buffer.from(credentials.username ?? '', 'utf8');
  const portBuffer = Buffer.alloc(2);
  portBuffer.writeUInt16BE(target.port, 0);

  const ip = net.isIPv4(target.host) ? target.host : null;
  const header = ip
    ? Buffer.concat([Buffer.from([0x04, 0x01]), portBuffer, Buffer.from(ip.split('.').map(Number)), Buffer.from([0x00]), userid, Buffer.from([0x00])])
    : Buffer.concat([
        Buffer.from([0x04, 0x01]),
        portBuffer,
        Buffer.from([0x00, 0x00, 0x00, 0x01]),
        Buffer.from([0x00]),
        userid,
        Buffer.from([0x00]),
        Buffer.from(target.host, 'utf8'),
        Buffer.from([0x00]),
      ]);
  socket.write(header);

  const reply = await readExactly(socket, 8);
  if (reply[1] !== 0x5a) throw new Error(`SOCKS4: connect failed (code ${reply[1]})`);
}
