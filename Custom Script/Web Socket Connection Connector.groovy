/*------------------------------------------------/
Script Name: WebSocket Client Process Script
Creation Date: 08-10-2019
Author: Mitchell Franklin
Updated Date: 2024-07-15
Updated By: Mitchell franklin
Description:
  Provides WebSocket connectivity for Dell Boomi processes.
  Supports ws:// and wss:// with an optional persistent-connection
  mode that reuses a single handshake across many documents.

  This script implements the WebSocket protocol as defined in
  RFC 6455 (https://tools.ietf.org/html/rfc6455).

═══════════════════════════════════════════════════
 Dynamic Process Properties (DPPs)
 Set these once per process execution via a
 Set Properties shape before this scripting step.
═══════════════════════════════════════════════════
  dpp_ws_server                – (required) Hostname of the WebSocket server
  dpp_ws_port                  – Port number (default: 80 for ws, 443 for wss)
  dpp_ws_path                  – URL path on the server, e.g. "/ws/api"
                                  (default: "/")
  dpp_ws_use_tls               – "true" to enable wss:// / TLS encryption
                                  (default: "false")
  dpp_ws_timeout_ms            – Socket connect and read timeout in
                                  milliseconds (default: "30000")
  dpp_ws_extra_headers         – Additional HTTP headers to include in the
                                  handshake. Separate multiple headers with
                                  a pipe character:
                                  "Authorization:Bearer abc|X-Tenant:123"
  dpp_ws_subprotocol           – Value for the Sec-WebSocket-Protocol header
                                  (optional; omit if not needed)
  dpp_ws_read_response         – "true" to wait for and capture a response
                                  frame after each send (default: "true")
  dpp_ws_persistent            – "true"  = one handshake, many documents
                                  "false" = new handshake per document
                                  (default: "true")
  dpp_ws_ping_interval_ms      – If greater than zero, sends a WebSocket
                                  ping frame at this interval to keep the
                                  connection alive through proxies and load
                                  balancers (default: "0" = disabled)
  dpp_ws_max_retries           – How many times to retry the handshake or
                                  reconnect if the connection drops during
                                  a batch (default: "1")
  dpp_ws_max_docs_per_connection – In persistent mode, close and re-establish
                                    the socket after this many documents have
                                    been sent. Helps avoid resource exhaustion
                                    on very large batches.
                                    (default: "0" = unlimited)

═══════════════════════════════════════════════════
 Dynamic Document Properties (DDPs)
 Set these per document on the source side.
═══════════════════════════════════════════════════
  ddp_ws_payload    – Explicit payload for this document. When set, the
                       document stream content is ignored.
  ddp_ws_close_code – Status code for the WebSocket close frame. Only
                       meaningful for the final close in persistent mode,
                       or the per-document close in non-persistent mode.
                       (default: "1000" = normal closure)

═══════════════════════════════════════════════════
 Output (written as DPPs after execution)
═══════════════════════════════════════════════════
  dpp_ws_last_status      – "OK" | "ERROR" | "FATAL"
  dpp_ws_last_response    – The most recent response frame payload
  dpp_ws_last_error       – Error description when status is ERROR or FATAL
  dpp_ws_documents_sent   – Count of documents successfully sent
  dpp_ws_documents_failed – Count of documents that failed

  In persistent mode each document also receives:
    ddp_ws_response       – Response text for this specific document
                             (accessible on the document properties
                             downstream)
/-------------------------------------------------*/

import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.MessageDigest

// ═══════════════════════════════════════════════════════════════════════════
//  Named constants — no magic numbers
// ═══════════════════════════════════════════════════════════════════════════

// WebSocket opcodes (RFC 6455 §5.2)
class WebSocketOpcode {
    static final int CONTINUATION = 0x00
    static final int TEXT         = 0x01
    static final int BINARY       = 0x02
    static final int CLOSE        = 0x08
    static final int PING         = 0x09
    static final int PONG         = 0x0A
}

// WebSocket close status codes (RFC 6455 §7.4)
class WebSocketCloseCode {
    static final int NORMAL                  = 1000
    static final int GOING_AWAY              = 1001
    static final int PROTOCOL_ERROR          = 1002
    static final int UNSUPPORTED_DATA        = 1003
    static final int NO_STATUS_RECEIVED      = 1005
    static final int ABNORMAL_CLOSURE        = 1006
    static final int INVALID_PAYLOAD         = 1007
    static final int POLICY_VIOLATION        = 1008
    static final int MESSAGE_TOO_BIG         = 1009
    static final int MANDATORY_EXTENSION     = 1010
    static final int INTERNAL_SERVER_ERROR   = 1011
}

// WebSocket magic GUID used during handshake key validation (RFC 6455 §4.2.2)
final String WEBSOCKET_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// FIN bit + RSV bits clear = 0x80 (RFC 6455 §5.2)
final int FRAME_FIN_BIT = 0x80

// Mask bit for client-to-server frames (RFC 6455 §5.3)
final int FRAME_MASK_BIT = 0x80

// Payload length thresholds (RFC 6455 §5.2)
final int PAYLOAD_LENGTH_16BIT_THRESHOLD = 126
final int PAYLOAD_LENGTH_64BIT_THRESHOLD = 127

// Number of bytes in a masking key (RFC 6455 §5.3)
final int MASKING_KEY_LENGTH = 4

// Standard HTTP port assignments
final int DEFAULT_HTTP_PORT  = 80
final int DEFAULT_HTTPS_PORT = 443

// Default configuration values
final String DEFAULT_PATH               = "/"
final String DEFAULT_TIMEOUT_MS         = "30000"
final String DEFAULT_USE_TLS            = "false"
final String DEFAULT_READ_RESPONSE      = "true"
final String DEFAULT_PERSISTENT         = "true"
final String DEFAULT_PING_INTERVAL_MS   = "0"
final String DEFAULT_MAX_RETRIES        = "1"
final String DEFAULT_MAX_DOCS_PER_CONN  = "0"
final String DEFAULT_CLOSE_CODE         = "1000"

// Retry delay between reconnect attempts (milliseconds)
final int RECONNECT_DELAY_MS = 1000

// Polling sleep when waiting for socket data
final int READ_POLL_SLEEP_MS = 10

// ═══════════════════════════════════════════════════════════════════════════
//  Helper — read a Dynamic Process Property with a fallback default
// ═══════════════════════════════════════════════════════════════════════════

String readDpp(String propertyName, String defaultValue = null) {
    String value = ExecutionUtil.getDynamicProcessProperty(propertyName)
    if (value != null && !value.isEmpty()) {
        return value
    }
    return defaultValue
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helper — read a Dynamic Document Property with a fallback default
// ═══════════════════════════════════════════════════════════════════════════

String readDdp(Properties documentProperties, String propertyName, String defaultValue = null) {
    String value = documentProperties.getProperty(propertyName)
    if (value != null && !value.isEmpty()) {
        return value
    }
    return defaultValue
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helper — extract the payload for a single document
// ═══════════════════════════════════════════════════════════════════════════

String extractDocumentPayload(InputStream documentStream, Properties documentProperties) {
    // If the document carries an explicit payload override, use it
    String explicitPayload = readDdp(documentProperties, "ddp_ws_payload", null)
    if (explicitPayload != null) {
        return explicitPayload
    }

    // Otherwise read the body of the incoming document stream
    StringBuilder contentBuilder = new StringBuilder()
    BufferedReader reader = null
    try {
        reader = new BufferedReader(new InputStreamReader(documentStream, "UTF-8"))
        String line
        while ((line = reader.readLine()) != null) {
            contentBuilder.append(line)
        }
    } finally {
        if (reader != null) {
            reader.close()
        }
    }
    return contentBuilder.toString()
}

// ═══════════════════════════════════════════════════════════════════════════
//  WebSocket frame construction (RFC 6455 §5.2–§5.3)
//  Every client-to-server frame must include a 4-byte random masking key.
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Builds a complete, masked WebSocket frame ready to write to the socket.
 *
 * Frame layout (RFC 6455 §5.2):
 *   Byte 0:       FIN(1) | RSV(3) | Opcode(4)
 *   Byte 1:       MASK(1) | Payload Length(7)
 *   Bytes 2–3/9:  Extended payload length (if needed)
 *   Bytes +0–+3:  Masking key (4 bytes, present only when MASK=1)
 *   Bytes +4–end:  Masked payload
 */
byte[] buildMaskedFrame(int opcode, byte[] payloadData) {
    byte[] maskKey = generateMaskingKey()
    int payloadLength = payloadData.length

    ByteArrayOutputStream frameBuffer = new ByteArrayOutputStream()

    // --- Byte 0: FIN=1, RSV=0, opcode --------------------------------------
    frameBuffer.write(FRAME_FIN_BIT | (opcode & 0x0F))

    // --- Byte 1 and optional extended length -------------------------------
    if (payloadLength < PAYLOAD_LENGTH_16BIT_THRESHOLD) {
        // 7-bit length, mask bit set
        frameBuffer.write(FRAME_MASK_BIT | payloadLength)
    } else if (payloadLength <= 0xFFFF) {
        // 16-bit extended length (value 126 signals this mode)
        frameBuffer.write(FRAME_MASK_BIT | PAYLOAD_LENGTH_16BIT_THRESHOLD)
        frameBuffer.write((payloadLength >> 8) & 0xFF)
        frameBuffer.write(payloadLength & 0xFF)
    } else {
        // 64-bit extended length (value 127 signals this mode)
        frameBuffer.write(FRAME_MASK_BIT | PAYLOAD_LENGTH_64BIT_THRESHOLD)
        for (int shift = 56; shift >= 0; shift -= 8) {
            frameBuffer.write((int) ((payloadLength >> shift) & 0xFF))
        }
    }

    // --- Masking key (4 random bytes) --------------------------------------
    frameBuffer.write(maskKey, 0, MASKING_KEY_LENGTH)

    // --- Masked payload ----------------------------------------------------
    for (int byteIndex = 0; byteIndex < payloadLength; byteIndex++) {
        int maskedByte = payloadData[byteIndex] ^ maskKey[byteIndex % MASKING_KEY_LENGTH]
        frameBuffer.write(maskedByte)
    }

    return frameBuffer.toByteArray()
}

private byte[] generateMaskingKey() {
    byte[] key = new byte[MASKING_KEY_LENGTH]
    new SecureRandom().nextBytes(key)
    return key
}

/** Convenience: build a text frame (opcode 0x01). */
byte[] buildTextFrame(String message) {
    return buildMaskedFrame(WebSocketOpcode.TEXT, message.getBytes("UTF-8"))
}

/** Convenience: build a close frame (opcode 0x08). */
byte[] buildCloseFrame(int statusCode) {
    byte[] statusBytes = [
        (byte) ((statusCode >> 8) & 0xFF),
        (byte) (statusCode & 0xFF)
    ]
    return buildMaskedFrame(WebSocketOpcode.CLOSE, statusBytes)
}

/** Convenience: build a ping frame (opcode 0x09). */
byte[] buildPingFrame() {
    return buildMaskedFrame(WebSocketOpcode.PING, new byte[0])
}

/** Convenience: build a pong frame (opcode 0x0A). */
byte[] buildPongFrame(byte[] pingPayload) {
    return buildMaskedFrame(WebSocketOpcode.PONG, pingPayload)
}

// ═══════════════════════════════════════════════════════════════════════════
//  Frame result object — holds a parsed server frame
// ═══════════════════════════════════════════════════════════════════════════

class ParsedFrame {
    int     opcode
    String  textPayload     // meaningful only for TEXT frames
    int     closeStatusCode  // meaningful only for CLOSE frames
    String  closeReason      // meaningful only for CLOSE frames
    byte[]  rawPayload
}

// ═══════════════════════════════════════════════════════════════════════════
//  Frame reader — reads and parses a single frame from the server
//  Server-to-client frames are NOT masked (RFC 6455 §5.1).
// ═══════════════════════════════════════════════════════════════════════════

ParsedFrame readSingleFrame(InputStream inputStream, int timeoutMilliseconds) {
    long deadlineTimestamp = System.currentTimeMillis() + timeoutMilliseconds

    // --- Read the first two mandatory bytes ---------------------------------
    int firstByte  = readByteWithDeadline(inputStream, deadlineTimestamp)
    int secondByte = readByteWithDeadline(inputStream, deadlineTimestamp)

    int opcode = firstByte & 0x0F
    long payloadLength = secondByte & 0x7F  // mask bit is always 0 server→client

    // --- Decode extended payload length -------------------------------------
    if (payloadLength == PAYLOAD_LENGTH_16BIT_THRESHOLD) {
        payloadLength = ((readByteWithDeadline(inputStream, deadlineTimestamp) & 0xFF) << 8)
                      |  (readByteWithDeadline(inputStream, deadlineTimestamp) & 0xFF)
    } else if (payloadLength == PAYLOAD_LENGTH_64BIT_THRESHOLD) {
        payloadLength = 0L
        for (int octet = 0; octet < 8; octet++) {
            payloadLength = (payloadLength << 8)
                          | (readByteWithDeadline(inputStream, deadlineTimestamp) & 0xFF)
        }
    }

    // --- Read the payload ---------------------------------------------------
    byte[] payloadBytes = new byte[(int) payloadLength]
    int bytesRead = 0
    while (bytesRead < payloadBytes.length) {
        int chunk = inputStream.read(payloadBytes, bytesRead, payloadBytes.length - bytesRead)
        if (chunk < 0) {
            throw new EOFException(
                "WebSocket connection closed while reading frame payload " +
                "(${bytesRead} of ${payloadLength} bytes read)")
        }
        bytesRead += chunk
    }

    // --- Interpret the frame based on opcode --------------------------------
    ParsedFrame frame = new ParsedFrame()
    frame.opcode     = opcode
    frame.rawPayload = payloadBytes

    switch (opcode) {
        case WebSocketOpcode.TEXT:
            frame.textPayload = new String(payloadBytes, "UTF-8")
            break

        case WebSocketOpcode.CLOSE:
            if (payloadBytes.length >= 2) {
                int highByte = payloadBytes[0] & 0xFF
                int lowByte  = payloadBytes[1] & 0xFF
                frame.closeStatusCode = (highByte << 8) | lowByte
            } else {
                frame.closeStatusCode = WebSocketCloseCode.NO_STATUS_RECEIVED
            }
            if (payloadBytes.length > 2) {
                frame.closeReason = new String(payloadBytes, 2,
                                               payloadBytes.length - 2, "UTF-8")
            }
            break

        case WebSocketOpcode.PING:
        case WebSocketOpcode.PONG:
            // No additional parsing needed; rawPayload is available if needed
            break

        default:
            // Continuation (0x00) and binary (0x02) are not handled here
            // but the raw payload is still available on the frame object
            break
    }

    return frame
}

/**
 * Reads a single byte from the input stream, polling until data
 * arrives or the deadline expires.
 */
private int readByteWithDeadline(InputStream inputStream, long deadlineTimestamp) {
    while (System.currentTimeMillis() < deadlineTimestamp) {
        if (inputStream.available() > 0) {
            int byteValue = inputStream.read()
            if (byteValue < 0) {
                throw new EOFException(
                    "WebSocket connection closed unexpectedly by the server")
            }
            return byteValue
        }
        Thread.sleep(READ_POLL_SLEEP_MS)
    }
    throw new SocketTimeoutException(
        "Timed out waiting for data from the WebSocket server")
}

// ═══════════════════════════════════════════════════════════════════════════
//  TLS — create a socket factory that trusts all certificates
//  ══════════════════════════════════════════════════════════════════════════
//  WARNING: This bypasses certificate validation, which is acceptable
//  for internal / development use but not for production internet-facing
//  integrations. For production, replace with a proper keystore-backed
//  SSLContext.
// ═══════════════════════════════════════════════════════════════════════════

private SSLSocketFactory createTrustAllSslSocketFactory() {
    TrustManager[] trustAllCerts = [
        new X509TrustManager() {
            X509Certificate[] getAcceptedIssuers() {
                return null
            }
            void checkClientTrusted(X509Certificate[] certificates, String authType) {
                // Trust all clients
            }
            void checkServerTrusted(X509Certificate[] certificates, String authType) {
                // Trust all servers
            }
        }
    ] as TrustManager[]

    SSLContext sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustAllCerts, new SecureRandom())
    return sslContext.getSocketFactory()
}

// ═══════════════════════════════════════════════════════════════════════════
//  WebSocket handshake — HTTP Upgrade (RFC 6455 §4)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Opens a TCP (or TLS) socket to the server, performs the HTTP Upgrade
 * handshake, validates the response, and returns the connected socket
 * ready for WebSocket framing.
 */
private Socket performWebSocketHandshake(
        String serverHost,
        int serverPort,
        String urlPath,
        String extraHeaders,
        String subprotocol,
        boolean useTls,
        int timeoutMilliseconds) {

    // --- 1. Open the underlying socket -------------------------------------
    Socket socket
    if (useTls) {
        SSLSocketFactory factory = createTrustAllSslSocketFactory()
        socket = factory.createSocket(serverHost, serverPort)
    } else {
        socket = new Socket(serverHost, serverPort)
    }
    socket.setSoTimeout(timeoutMilliseconds)

    // --- 2. Generate the Sec-WebSocket-Key (16 random bytes, base64) --------
    byte[] nonceBytes = new byte[16]
    new SecureRandom().nextBytes(nonceBytes)
    String clientKey = Base64.getEncoder().encodeToString(nonceBytes)

    // --- 3. Send the HTTP Upgrade request ----------------------------------
    PrintWriter writer = new PrintWriter(
        new OutputStreamWriter(socket.getOutputStream(), "UTF-8"),
        true)  // autoFlush = true

    writer.println("GET " + urlPath + " HTTP/1.1")
    writer.println("Host: " + serverHost + ":" + serverPort)
    writer.println("Upgrade: websocket")
    writer.println("Connection: Upgrade")
    writer.println("Sec-WebSocket-Key: " + clientKey)
    writer.println("Sec-WebSocket-Version: 13")

    if (subprotocol != null && !subprotocol.isEmpty()) {
        writer.println("Sec-WebSocket-Protocol: " + subprotocol)
    }

    if (extraHeaders != null && !extraHeaders.isEmpty()) {
        String[] headerArray = extraHeaders.split("\\|")
        for (String header : headerArray) {
            writer.println(header.trim())
        }
    }

    writer.println()   // blank line terminates the request
    writer.flush()

    // --- 4. Read the HTTP response -----------------------------------------
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(socket.getInputStream(), "UTF-8"))

    String statusLine = reader.readLine()
    if (statusLine == null || !statusLine.contains("101")) {
        // The server did not agree to upgrade — capture the response for debugging
        StringBuilder responseCapture = new StringBuilder()
        responseCapture.append(statusLine != null ? statusLine : "(empty response)")
        String headerLine
        while ((headerLine = reader.readLine()) != null && !headerLine.isEmpty()) {
            responseCapture.append("\n").append(headerLine)
        }
        socket.close()
        throw new IOException(
            "WebSocket handshake was rejected by the server. " +
            "Expected HTTP 101, got:\n" + responseCapture.toString())
    }

    // --- 5. Validate the Sec-WebSocket-Accept header -----------------------
    // Per RFC 6455 §4.2.2: the server must respond with the base64-encoded
    // SHA-1 hash of (clientKey + magic GUID).
    String combinedForHash = clientKey + WEBSOCKET_MAGIC_GUID
    MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1")
    byte[] hashBytes = sha1Digest.digest(combinedForHash.getBytes("UTF-8"))
    String expectedAccept = Base64.getEncoder().encodeToString(hashBytes)

    String actualAccept = null
    String responseHeader
    while ((responseHeader = reader.readLine()) != null && !responseHeader.isEmpty()) {
        if (responseHeader.toLowerCase().startsWith("sec-websocket-accept:")) {
            int colonIndex = responseHeader.indexOf(":")
            actualAccept = responseHeader.substring(colonIndex + 1).trim()
        }
    }

    if (actualAccept == null || !actualAccept.equals(expectedAccept)) {
        socket.close()
        throw new IOException(
            "WebSocket handshake validation failed. " +
            "The server's Sec-WebSocket-Accept header did not match the expected value. " +
            "Expected: " + expectedAccept + ", Got: " + actualAccept)
    }

    return socket
}

// ═══════════════════════════════════════════════════════════════════════════
//  Connection wrapper — bundles a socket with its streams and state
// ═══════════════════════════════════════════════════════════════════════════

class WebSocketConnection {
    Socket       rawSocket
    OutputStream outputStream
    InputStream  inputStream
    int          timeoutMilliseconds
    long         pingIntervalMilliseconds
    long         lastActivityTimestamp
    boolean      intentionallyClosed = false

    /**
     * Sends a pre-built frame to the server.
     */
    void sendFrame(byte[] frameBytes) throws IOException {
        if (intentionallyClosed) {
            throw new IOException("Cannot send on a closed connection")
        }
        outputStream.write(frameBytes)
        outputStream.flush()
        lastActivityTimestamp = System.currentTimeMillis()
    }

    /**
     * Reads and returns the next complete frame from the server.
     */
    ParsedFrame readNextFrame() throws IOException {
        if (intentionallyClosed) {
            throw new IOException("Cannot read from a closed connection")
        }
        ParsedFrame frame = readSingleFrame(inputStream, timeoutMilliseconds)
        lastActivityTimestamp = System.currentTimeMillis()
        return frame
    }

    /**
     * Sends a ping frame to help keep the connection alive.
     * Does not wait for a pong — the next read or write will
     * detect a dead connection naturally.
     */
    void sendPing() throws IOException {
        if (intentionallyClosed) {
            return
        }
        sendFrame(buildPingFrame())
    }

    /**
     * Sends a graceful close frame and marks this connection as closed.
     */
    void sendCloseFrameAndMarkClosed(int statusCode) {
        if (intentionallyClosed) {
            return
        }
        intentionallyClosed = true
        try {
            sendFrame(buildCloseFrame(statusCode))
        } catch (IOException ignored) {
            // Best effort — the socket may already be dead
        }
    }

    /**
     * Fully disconnects: sends a close frame (best effort)
     * and then closes the underlying socket.
     */
    void disconnect(int closeStatusCode) {
        sendCloseFrameAndMarkClosed(closeStatusCode)
        try {
            if (rawSocket != null) {
                rawSocket.close()
            }
        } catch (IOException ignored) {
            // Nothing we can do
        }
    }

    /**
     * Returns true if this connection appears to be dead.
     */
    boolean isDead() {
        if (intentionallyClosed) {
            return true
        }
        if (rawSocket == null) {
            return true
        }
        if (rawSocket.isClosed()) {
            return true
        }
        return false
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Reconnect logic — attempts to (re)establish a handshake up to maxRetries
//  times, with a short delay between attempts.
// ═══════════════════════════════════════════════════════════════════════════

private WebSocketConnection establishConnectionWithRetries(
        String serverHost,
        int serverPort,
        String urlPath,
        String extraHeaders,
        String subprotocol,
        boolean useTls,
        int timeoutMilliseconds,
        long pingIntervalMilliseconds,
        int maxRetries) {

    int attemptsRemaining = maxRetries

    while (true) {
        try {
            Socket socket = performWebSocketHandshake(
                serverHost, serverPort, urlPath, extraHeaders,
                subprotocol, useTls, timeoutMilliseconds)

            WebSocketConnection connection = new WebSocketConnection()
            connection.rawSocket               = socket
            connection.outputStream            = socket.getOutputStream()
            connection.inputStream             = socket.getInputStream()
            connection.timeoutMilliseconds     = timeoutMilliseconds
            connection.pingIntervalMilliseconds = pingIntervalMilliseconds
            connection.lastActivityTimestamp   = System.currentTimeMillis()

            return connection

        } catch (Exception handshakeError) {
            attemptsRemaining--
            if (attemptsRemaining < 0) {
                throw new Exception(
                    "Failed to establish WebSocket connection after " +
                    (maxRetries + 1) + " attempt(s). " +
                    "Last error: " + handshakeError.getMessage(),
                    handshakeError)
            }
            ExecutionUtil.setDynamicProcessProperty(
                "dpp_ws_connection_retry",
                "Handshake failed (" + handshakeError.getMessage() + "). " +
                "Retries left: " + (attemptsRemaining + 1) + ". " +
                "Waiting " + RECONNECT_DELAY_MS + "ms before retrying.",
                false)
            Thread.sleep(RECONNECT_DELAY_MS)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Main processing
// ═══════════════════════════════════════════════════════════════════════════

try {
    // ── Gather configuration from Dynamic Process Properties ────────────

    String serverHostname = readDpp("dpp_ws_server")
    if (serverHostname == null || serverHostname.isEmpty()) {
        throw new IllegalArgumentException(
            "The Dynamic Process Property 'dpp_ws_server' is required. " +
            "Please set it to the WebSocket server hostname using a " +
            "Set Properties shape before this scripting step.")
    }

    int serverPort = Integer.parseInt(
        readDpp("dpp_ws_port", "0"))

    String urlPath = readDpp("dpp_ws_path", DEFAULT_PATH)

    boolean useTlsEncryption = Boolean.parseBoolean(
        readDpp("dpp_ws_use_tls", DEFAULT_USE_TLS))

    int timeoutMilliseconds = Integer.parseInt(
        readDpp("dpp_ws_timeout_ms", DEFAULT_TIMEOUT_MS))

    String extraHeaders = readDpp("dpp_ws_extra_headers", "")

    String subprotocol = readDpp("dpp_ws_subprotocol", "")

    boolean readResponseAfterSend = Boolean.parseBoolean(
        readDpp("dpp_ws_read_response", DEFAULT_READ_RESPONSE))

    boolean persistentMode = Boolean.parseBoolean(
        readDpp("dpp_ws_persistent", DEFAULT_PERSISTENT))

    long pingIntervalMilliseconds = Long.parseLong(
        readDpp("dpp_ws_ping_interval_ms", DEFAULT_PING_INTERVAL_MS))

    int maxRetries = Integer.parseInt(
        readDpp("dpp_ws_max_retries", DEFAULT_MAX_RETRIES))

    int maxDocumentsPerConnection = Integer.parseInt(
        readDpp("dpp_ws_max_docs_per_connection", DEFAULT_MAX_DOCS_PER_CONN))

    // Default port based on encryption setting
    if (serverPort == 0) {
        serverPort = useTlsEncryption ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT
    }

    // ── Counters ────────────────────────────────────────────────────────

    int totalDocuments     = dataContext.getDataCount()
    int documentsSentOk    = 0
    int documentsFailed    = 0
    String lastResponse    = null
    String lastError       = null

    // ── Persistent mode — one handshake, many documents ─────────────────
    if (persistentMode) {

        WebSocketConnection connection = null
        long lastPingTimestamp = System.currentTimeMillis()
        int documentsSentOnThisConnection = 0

        try {
            // Initial handshake
            connection = establishConnectionWithRetries(
                serverHostname, serverPort, urlPath, extraHeaders,
                subprotocol, useTlsEncryption, timeoutMilliseconds,
                pingIntervalMilliseconds, maxRetries)

            // Process each document
            for (int documentIndex = 0; documentIndex < totalDocuments; documentIndex++) {

                InputStream documentStream   = dataContext.getStream(documentIndex)
                Properties documentProperties = dataContext.getProperties(documentIndex)

                // ── Check if we need to cycle the connection ────────────
                // This prevents resource exhaustion on very large batches
                // by periodically closing and re-handshaking.
                if (maxDocumentsPerConnection > 0 &&
                    documentsSentOnThisConnection >= maxDocumentsPerConnection) {

                    connection.disconnect(WebSocketCloseCode.NORMAL)
                    ExecutionUtil.setDynamicProcessProperty(
                        "dpp_ws_connection_cycle",
                        "Cycling connection after " + documentsSentOnThisConnection +
                        " documents (limit: " + maxDocumentsPerConnection + "). " +
                        "Documents processed so far: " + (sentOk + failed) + " / " + totalDocuments,
                        false)

                    connection = establishConnectionWithRetries(
                        serverHostname, serverPort, urlPath, extraHeaders,
                        subprotocol, useTlsEncryption, timeoutMilliseconds,
                        pingIntervalMilliseconds, maxRetries)

                    documentsSentOnThisConnection = 0
                    lastPingTimestamp = System.currentTimeMillis()
                }

                // ── Check if the connection died and reconnect ──────────
                if (connection.isDead()) {
                    ExecutionUtil.setDynamicProcessProperty(
                        "dpp_ws_reconnect",
                        "Connection dropped at document " + documentIndex +
                        ". Attempting to reconnect...",
                        false)

                    connection = establishConnectionWithRetries(
                        serverHostname, serverPort, urlPath, extraHeaders,
                        subprotocol, useTlsEncryption, timeoutMilliseconds,
                        pingIntervalMilliseconds, maxRetries)

                    documentsSentOnThisConnection = 0
                    lastPingTimestamp = System.currentTimeMillis()
                }

                // ── Keepalive ping ──────────────────────────────────────
                if (pingIntervalMilliseconds > 0) {
                    long elapsedSinceLastPing =
                        System.currentTimeMillis() - lastPingTimestamp
                    if (elapsedSinceLastPing >= pingIntervalMilliseconds) {
                        connection.sendPing()
                        lastPingTimestamp = System.currentTimeMillis()
                    }
                }

                // ── Extract payload and send ────────────────────────────
                try {
                    String payload = extractDocumentPayload(documentStream, documentProperties)

                    if (payload == null || payload.isEmpty()) {
                        ExecutionUtil.setDynamicProcessProperty(
                            "dpp_ws_last_warning",
                            "Document at index " + documentIndex +
                            " has an empty payload; skipping.",
                            false)
                        continue
                    }

                    connection.sendFrame(buildTextFrame(payload))
                    documentsSentOk++
                    documentsSentOnThisConnection++

                    // ── Read response if enabled ────────────────────────
                    if (readResponseAfterSend) {
                        ParsedFrame responseFrame = connection.readNextFrame()

                        switch (responseFrame.opcode) {

                            case WebSocketOpcode.TEXT:
                                lastResponse = responseFrame.textPayload
                                documentProperties.setProperty(
                                    "ddp_ws_response", responseFrame.textPayload)
                                break

                            case WebSocketOpcode.CLOSE:
                                lastResponse = "[Server closed connection] " +
                                    "code=" + responseFrame.closeStatusCode +
                                    ", reason=" + responseFrame.closeReason
                                documentProperties.setProperty(
                                    "ddp_ws_response",
                                    "CLOSE:" + responseFrame.closeStatusCode +
                                    ":" + responseFrame.closeReason)
                                // Mark connection so we reconnect on next iteration
                                connection.intentionallyClosed = true
                                break

                            case WebSocketOpcode.PING:
                                connection.sendFrame(
                                    buildPongFrame(responseFrame.rawPayload))
                                lastResponse = "[PING received — pong sent]"
                                documentProperties.setProperty(
                                    "ddp_ws_response", "PING")
                                break

                            default:
                                lastResponse = "[Unhandled opcode: " +
                                    responseFrame.opcode + "]"
                                documentProperties.setProperty(
                                    "ddp_ws_response",
                                    "OPCODE:" + responseFrame.opcode)
                                break
                        }
                    }

                } catch (Exception documentError) {
                    documentsFailed++
                    documentProperties.setProperty(
                        "ddp_ws_response",
                        "ERROR:" + documentError.getMessage())
                    ExecutionUtil.setDynamicProcessProperty(
                        "dpp_ws_document_" + documentIndex + "_error",
                        documentError.toString(),
                        false)
                    // Force a reconnect on the next iteration
                    connection.intentionallyClosed = true
                }
            }

            // ── Graceful close at end of batch ─────────────────────────
            if (connection != null) {
                connection.disconnect(WebSocketCloseCode.NORMAL)
            }

        } catch (Exception outerError) {
            // Something went wrong at the connection level (not per-document)
            lastError = outerError.toString()
            if (connection != null) {
                try {
                    connection.disconnect(WebSocketCloseCode.ABNORMAL_CLOSURE)
                } catch (Exception ignored) {
                    // Already dead
                }
            }
            throw outerError
        }

    // ── Non-persistent mode — handshake per document ───────────────────
    } else {

        for (int documentIndex = 0; documentIndex < totalDocuments; documentIndex++) {

            InputStream documentStream   = dataContext.getStream(documentIndex)
            Properties documentProperties = dataContext.getProperties(documentIndex)
            Socket singleUseSocket       = null

            try {
                String payload = extractDocumentPayload(documentStream, documentProperties)

                if (payload == null || payload.isEmpty()) {
                    ExecutionUtil.setDynamicProcessProperty(
                        "dpp_ws_last_warning",
                        "Document at index " + documentIndex +
                        " has an empty payload; skipping.",
                        false)
                    continue
                }

                // Handshake
                singleUseSocket = performWebSocketHandshake(
                    serverHostname, serverPort, urlPath, extraHeaders,
                    subprotocol, useTlsEncryption, timeoutMilliseconds)

                // Send the text frame
                singleUseSocket.getOutputStream().write(buildTextFrame(payload))
                singleUseSocket.getOutputStream().flush()
                documentsSentOk++

                // Optionally read a response
                if (readResponseAfterSend) {
                    ParsedFrame responseFrame = readSingleFrame(
                        singleUseSocket.getInputStream(), timeoutMilliseconds)

                    switch (responseFrame.opcode) {
                        case WebSocketOpcode.TEXT:
                            lastResponse = responseFrame.textPayload
                            documentProperties.setProperty(
                                "ddp_ws_response", responseFrame.textPayload)
                            break
                        case WebSocketOpcode.CLOSE:
                            lastResponse = "[Server closed] code=" +
                                responseFrame.closeStatusCode
                            documentProperties.setProperty(
                                "ddp_ws_response",
                                "CLOSE:" + responseFrame.closeStatusCode +
                                ":" + responseFrame.closeReason)
                            break
                        default:
                            lastResponse = "[Opcode " + responseFrame.opcode + "]"
                            documentProperties.setProperty(
                                "ddp_ws_response",
                                "OPCODE:" + responseFrame.opcode)
                            break
                    }
                }

                // Close this document's connection
                int closeStatusCode = Integer.parseInt(
                    readDdp(documentProperties, "ddp_ws_close_code", DEFAULT_CLOSE_CODE))
                singleUseSocket.getOutputStream().write(buildCloseFrame(closeStatusCode))
                singleUseSocket.getOutputStream().flush()

            } catch (Exception documentError) {
                documentsFailed++
                documentProperties.setProperty(
                    "ddp_ws_response",
                    "ERROR:" + documentError.getMessage())
                ExecutionUtil.setDynamicProcessProperty(
                    "dpp_ws_document_" + documentIndex + "_error",
                    documentError.toString(),
                    false)
            } finally {
                if (singleUseSocket != null) {
                    try {
                        singleUseSocket.close()
                    } catch (IOException ignored) {
                        // Best effort
                    }
                }
            }
        }
    }

    // ── Write final status DPPs ────────────────────────────────────────

    String finalStatus
    if (documentsFailed == 0) {
        finalStatus = "OK"
    } else if (documentsSentOk == 0) {
        finalStatus = "FATAL"
    } else {
        finalStatus = "ERROR"
    }

    ExecutionUtil.setDynamicProcessProperty("dpp_ws_last_status", finalStatus, false)
    ExecutionUtil.setDynamicProcessProperty("dpp_ws_last_response",
        lastResponse != null ? lastResponse : "", false)
    ExecutionUtil.setDynamicProcessProperty("dpp_ws_last_error",
        lastError != null ? lastError : "", false)
    ExecutionUtil.setDynamicProcessProperty("dpp_ws_documents_sent",
        String.valueOf(documentsSentOk), false)
    ExecutionUtil.setDynamicProcessProperty("dpp_ws_documents_failed",
        String.valueOf(documentsFailed), false)

    if (finalStatus == "FATAL") {
        throw new Exception(
            "All " + totalDocuments + " document(s) failed to send. " +
            "Check dpp_ws_last_error for details.")
    }

} catch (Exception exception) {
    ExecutionUtil.setDynamicProcessProperty(
        "dpp_scriptingTryCatch", exception.toString(), true)
    ExecutionUtil.setDynamicProcessProperty(
        "dpp_ws_last_status", "FATAL", false)
    ExecutionUtil.setDynamicProcessProperty(
        "dpp_ws_last_error", exception.toString(), false)
    ExecutionUtil.setDynamicProcessProperty(
        "dpp_ws_documents_sent", "0", false)
    ExecutionUtil.setDynamicProcessProperty(
        "dpp_ws_documents_failed",
        String.valueOf(dataContext.getDataCount()), false)
    throw exception
}
