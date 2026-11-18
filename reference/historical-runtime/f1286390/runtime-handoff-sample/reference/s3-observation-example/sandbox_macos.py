"""macOS sandbox profile for an explicitly supplied, pinned SeaweedFS binary."""
import json
import socket


def free_ports(n):
    holders = []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(('127.0.0.1', 0))
            holders.append(s)
        return [s.getsockname()[1] for s in holders]
    finally:
        for s in holders:
            s.close()


def profile_text(binary, work, ports, grpc_sockets):
    # Paths come from the local fixture, never from an observation bundle.
    q = json.dumps
    local = '\n'.join(f'(local ip "localhost:{p}")' for p in ports)
    remote = '\n'.join(f'(remote ip "localhost:{p}")' for p in ports)
    socket_paths = [str(p) for p in grpc_sockets] + [str(p).replace('/private/tmp/', '/tmp/', 1) for p in grpc_sockets]
    socket_files = ' '.join(f'(literal {q(p)})' for p in socket_paths)
    socket_local = ' '.join(f'(local unix-socket (literal {q(p)}))' for p in socket_paths)
    socket_remote = ' '.join(f'(remote unix-socket (literal {q(p)}))' for p in socket_paths)
    return f'''(version 1)
(deny default)
(import "/System/Library/Sandbox/Profiles/dyld-support.sb")
(allow process-exec (literal {q(str(binary))}) (literal "/usr/bin/curl"))
(allow process-fork)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read-metadata)
(allow file-map-executable (subpath "/System") (subpath "/usr") (literal {q(str(binary))}))
(allow file-read* (subpath "/System") (subpath "/usr") (subpath "/Library/Apple") (subpath "/private/var/db") (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random") (literal "/private/etc/hosts") (literal "/private/etc/localtime") (literal "/private/etc/ssl/openssl.cnf") (subpath {q(str(binary.parent))}) (subpath {q(str(work))}))
(allow file-read* {socket_files})
(allow file-write* (subpath {q(str(work))}) (literal "/dev/null") {socket_files})
(allow network-bind {local} (local unix-socket (subpath {q(str(work))})) {socket_local})
(allow network-inbound {local} (local unix-socket (subpath {q(str(work))})) {socket_local})
(allow network-outbound {remote} (remote unix-socket (subpath {q(str(work))})) {socket_remote})
'''

