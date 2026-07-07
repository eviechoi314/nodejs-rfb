import { SocketBuffer } from '../socketbuffer';
import { ISecurityType, ISecurityTypeHooks } from './securitytype';
import * as net from 'node:net';

export class NoneSecurityType implements ISecurityType {
	getName() {
		return 'Unauthenticated VNC';
	}

	async authenticate(rfbVer: string, socket: SocketBuffer, connection: net.Socket, auth: object, hooks: ISecurityTypeHooks): Promise<void> {
		// does nothing
	}
}
