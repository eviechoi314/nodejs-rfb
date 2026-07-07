import { SocketBuffer } from '../socketbuffer';
import { ISecurityType, ISecurityTypeHooks } from './securitytype';
import * as net from 'node:net';
import * as tls from 'node:tls';

/**
 * RFB security type 18 - GTK-VNC's "TLS" auth (GVNC_AUTH_TLS), used by
 * gnome-remote-desktop's VNC backend. Distinct from VeNCrypt (type 19):
 * no version sub-negotiation preamble, the TLS handshake begins immediately
 * on the raw socket once this type is selected. The server presents no
 * certificate - this is anonymous Diffie-Hellman, not certificate-based TLS,
 * so a normal cert-validating TLS client can't complete this handshake at all.
 *
 * After the TLS handshake completes, the protocol does not jump straight to
 * SecurityResult - it re-runs a full security-type sub-negotiation (same
 * count+list format as the outer one) inside the now-encrypted channel.
 * We surface that by returning the upgraded socket; the caller re-enters its
 * normal security-type handling loop on it, which naturally reaches the
 * existing VncSecurityType/NoneSecurityType for the inner round.
 *
 * That reuse is generic, not VNC-specific: NtlmSecurityType only ever talks
 * through the shared SocketBuffer/connection.write(), never the raw socket's
 * 'data' event directly, so a server offering type 18 -> type 4 (NTLM) for
 * the inner round would hit the exact same unmodified code path. Untested
 * (no server combining TLS with NTLM was available to verify against) - the
 * only nested pairing actually observed on the wire is 18 -> 2 (VNC-auth),
 * via gnome-remote-desktop.
 */
export class AnonTlsSecurityType implements ISecurityType {
	getName(): string {
		return 'TLS (Anonymous)';
	}

	async authenticate(rfbVer: string, socket: SocketBuffer, connection: net.Socket, auth: object, hooks: ISecurityTypeHooks): Promise<net.Socket> {
		// Stop our own listener consuming bytes meant for the TLS handshake
		// before handing the raw socket over to the tls module.
		hooks.detachDataListener();

		return new Promise((resolve, reject) => {
			const tlsSocket = tls.connect({
				socket: connection,
				rejectUnauthorized: false,
				// Anonymous key exchange has no TLS 1.3 equivalent (RFC 8446 dropped it).
				minVersion: 'TLSv1.2',
				maxVersion: 'TLSv1.2',
				// GnuTLS-side priority used by libvncclient for this security type is
				// "NORMAL:+ANON-ECDH:+ANON-DH" - mirror that ordering here.
				// @SECLEVEL=0 is required: OpenSSL 3.x disables anonymous ciphers by
				// default even though they're compiled in.
				ciphers: 'AECDH-AES256-SHA:AECDH-AES128-SHA:ADH-AES256-GCM-SHA384:ADH-AES128-GCM-SHA256:ADH-AES256-SHA:ADH-AES128-SHA:@SECLEVEL=0'
			});

			const onSecure = () => {
				tlsSocket.removeListener('error', onError);
				resolve(tlsSocket);
			};
			const onError = (err: Error) => {
				tlsSocket.removeListener('secureConnect', onSecure);
				reject(err);
			};

			tlsSocket.once('secureConnect', onSecure);
			tlsSocket.once('error', onError);
		});
	}
}
