# --- START OF MODIFIED vpn.py (Option 1: Harden TLS Settings) ---

import ssl
import socket
import os
import time
import logging
from typing import Optional

# Try to import cryptography for cert generation
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

# Configuration
CERT_FILE = "peer_cert.pem"
KEY_FILE = "peer_key.pem"
# Use module-level logger
log = logging.getLogger(__name__)

# --- ADDED: Recommended strong cipher list ---
# Prioritizes TLS 1.3 ciphers if available, then strong TLS 1.2
MODERN_CIPHERS = (
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:" # TLS 1.3
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
)
# --- END ADDED ---

def ensure_self_signed_cert(peer_id: str = "generic_peer") -> bool:
    """
    Ensures self-signed certificate and key files exist. Generates them if not.
    Returns True if files exist or were created successfully, False otherwise.
    (No changes needed in this function for Option 1)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        log.warning("Cannot generate TLS cert: 'cryptography' library not available.")
        return False # Indicate failure if crypto lib missing

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        log.debug(f"Existing TLS certificate ({CERT_FILE}) and key ({KEY_FILE}) found.")
        # Optional: Add validation (e.g., check expiry) - Keeping simple for now
        return True # Assume existing are okay

    log.info(f"Generating new self-signed TLS certificate ({CERT_FILE}) and key ({KEY_FILE})...")
    try:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # --- Determine SAN entries (Optional but good practice - included from prev suggestion) ---
        san_entries = []
        try:
            hostname = socket.getfqdn() # Fully qualified name
            # Ensure gethostbyname resolves the FQDN correctly
            ip_address_str = socket.gethostbyname(hostname)
            san_entries.append(x509.DNSName(hostname))
            # Convert IP string to IPAddress object
            san_entries.append(x509.IPAddress(socket.inet_aton(ip_address_str))) # Use inet_aton for IPv4
            common_name = hostname
            log.debug(f"Using SAN: DNS={hostname}, IP={ip_address_str}")
        except (socket.gaierror, socket.herror, OSError) as e: # Catch potential errors
            log.warning(f"Could not resolve hostname/IP for SAN ({e}). Using fallback CN.")
            common_name = f"peer-{peer_id[:8]}.p2p.local" # Fallback CN
            san_entries.append(x509.DNSName(common_name)) # Fallback SAN


        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"XX"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"DefaultState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"DefaultCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"P2PNetworkNode"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name), # Use determined CN
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Extend validity slightly to reduce regeneration frequency
            datetime.utcnow() + timedelta(days=730) # 2 year validity
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        # --- Add SAN extension ---
        ).add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False, # Usually False for SAN
        # --- End SAN addition ---
        ).sign(key, hashes.SHA256())

        # Write private key
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        try: os.chmod(KEY_FILE, 0o600)
        except OSError: pass

        # Write public certificate
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info("Successfully generated self-signed certificate and key with SAN.")
        return True

    except Exception as e:
        log.error(f"Failed to generate self-signed certificate: {e}", exc_info=True)
        # Clean up potentially partial files
        if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
        if os.path.exists(CERT_FILE): os.remove(CERT_FILE)
        return False


def create_server_context() -> Optional[ssl.SSLContext]:
    """
    Creates an SSL context for the server side, loading cert and key.
    MODIFIED: Sets minimum TLS version and restricts ciphers.
    """
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
         log.error(f"Server SSL context creation failed: Cert ({CERT_FILE}) or Key ({KEY_FILE}) not found.")
         return None
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

        # --- MODIFICATIONS FOR OPTION 1 ---
        try:
            # Require TLS 1.2 or higher (Python 3.7+ needed for TLSVersion enum)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            log.warning("Could not set minimum_version (requires Python 3.7+). Relying on default.")
            # For older Python, might need options like:
            # context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            # Use strong cipher list
            context.set_ciphers(MODERN_CIPHERS)
        except ssl.SSLError as cipher_err:
            log.error(f"Failed to set modern ciphers: {cipher_err}. Using system defaults.")
        # --- END MODIFICATIONS ---

        log.info("Server SSL context created successfully (TLSv1.2+, Modern Ciphers).")
        return context
    except ssl.SSLError as e:
        log.error(f"Error loading SSL cert/key for server context: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error creating server SSL context: {e}", exc_info=True)
        return None

def create_client_context() -> Optional[ssl.SSLContext]:
    """
    Creates an SSL context for the client side.
    WARNING: Disables certificate verification for self-signed cert compatibility.
             This is insecure and only suitable for demonstrations/testing.
    MODIFIED: Sets minimum TLS version and restricts ciphers.
    """
    try:
        # Purpose.SERVER_AUTH means we expect to verify a server cert (though we disable it)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # !!! --- SECURITY WARNING REMAINS --- !!!
        context.check_hostname = False      # Don't verify hostname matches cert CN/SAN
        context.verify_mode = ssl.CERT_NONE # Trust *any* certificate presented by server
        # !!! --- End Security Warning ---

        # --- MODIFICATIONS FOR OPTION 1 ---
        try:
            # Require TLS 1.2 or higher
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            log.warning("Could not set minimum_version (requires Python 3.7+). Relying on default.")
            # context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        try:
            # Use strong cipher list
            context.set_ciphers(MODERN_CIPHERS)
        except ssl.SSLError as cipher_err:
             log.error(f"Failed to set modern ciphers for client: {cipher_err}. Using system defaults.")
        # --- END MODIFICATIONS ---

        log.warning("Client SSL context created (TLSv1.2+, Modern Ciphers) - CERT VERIFICATION DISABLED.")
        return context
    except Exception as e:
        log.error(f"Unexpected error creating client SSL context: {e}", exc_info=True)
        return None


def receive_all_secure(ssock: ssl.SSLSocket, length: int, timeout: float) -> bytes:
    """
    Helper to receive exactly 'length' bytes from an SSL socket.
    Simplified blocking implementation with timeout.
    (No changes needed in this function for Option 1)
    """
    if length < 0: raise ValueError("Length cannot be negative")
    if length == 0: return b''

    data = bytearray()
    bytes_left = length
    start_time = time.monotonic()

    original_timeout = ssock.gettimeout()
    try:
        # Short timeout for individual calls to avoid indefinite block on SSLWantRead/Write
        # But still honor the overall timeout
        individual_timeout = max(0.05, min(timeout / 10, 0.5))

        while bytes_left > 0:
            # Check overall timeout first
            if time.monotonic() - start_time > timeout:
                 log.warning(f"SSL receive overall timeout ({timeout}s). Got {len(data)}/{length} bytes.")
                 raise socket.timeout(f"SSL receive overall timeout. Expected {length}, got {len(data)}")

            try:
                ssock.settimeout(individual_timeout) # Set short timeout for this attempt
                chunk_size = min(bytes_left, 16384) # Read in reasonable chunks
                chunk = ssock.recv(chunk_size)
                if not chunk:
                    log.warning(f"SSL socket closed during receive. Expected {length}, got {len(data)}.")
                    raise ConnectionAbortedError(f"SSL socket closed. Expected {length}, got {len(data)}.")

                data.extend(chunk)
                bytes_left -= len(chunk)

            except ssl.SSLWantReadError:
                # Need to wait for socket to become readable (underlying SSL ops)
                # Proper way is select(), but time.sleep is simpler for blocking code
                time.sleep(0.01) # Small sleep and retry
                continue
            except ssl.SSLWantWriteError:
                 # Need to wait for socket to become writable (underlying SSL ops)
                 time.sleep(0.01) # Small sleep and retry
                 continue
            except socket.timeout:
                 # Timeout on individual recv call - check overall timeout and continue if OK
                 if time.monotonic() - start_time > timeout:
                      raise # Re-raise if overall timeout exceeded
                 else:
                      continue # Continue waiting if overall time permits
            # Other exceptions (OSError, SSLError, ConnectionAbortedError) will propagate up

    finally:
        # Restore original socket timeout
        try:
            ssock.settimeout(original_timeout)
        except Exception: pass # Ignore errors setting timeout back

    # Check if we received the full amount after the loop (in case of ConnectionAbortedError)
    if len(data) != length:
         # This path might be taken if ConnectionAbortedError was raised and caught above
         log.warning(f"SSL receive ended prematurely. Expected {length}, got {len(data)}.")
         # Let caller handle potentially incomplete data

    return bytes(data)

# --- END OF MODIFIED vpn.py ---