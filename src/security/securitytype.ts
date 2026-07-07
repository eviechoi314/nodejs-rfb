import { SocketBuffer } from '../socketbuffer';
import * as net from 'node:net';

/**
 * Hooks a security type can use to interact with the owning VncClient's
 * transport. Only used by security types that need to swap the underlying
 * socket mid-handshake (e.g. TLS-wrapped auth) - most implementations ignore this.
 */
export interface ISecurityTypeHooks {
	/** Stop the client's own listener consuming raw socket data, e.g. before wrapping it in TLS. */
	detachDataListener(): void;
}

export interface ISecurityType {
	getName(): string;
	/**
	 * Returning a socket (instead of void) tells the caller to swap its
	 * connection to the returned socket and re-run security-type negotiation
	 * over it, rather than proceeding straight to SecurityResult.
	 */
	authenticate(rfbVer: string, socket: SocketBuffer, connection: net.Socket, auth: object, hooks: ISecurityTypeHooks): Promise<net.Socket | void>;
}
