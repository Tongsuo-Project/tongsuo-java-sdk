package org.conscrypt;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import net.tongsuo.TlcpKeyManagerImpl;
import net.tongsuo.TongsuoProvider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

public class TlcpDoubleCertTest {
    private final String TLCP = "TLCP";
    private final String HTTP_1_1 = "http/1.1";
    private final String HTTP_2 = "h2";
    private final String SNI_HOST_NAME = "example.com";
    private final Map<String, Object> CIPHER_SUIT_MAP = new HashMap<>();

    private final String SERVER_ENC_ALIAS = "SERVER_ENC_ENTRY";
    private final String SERVER_SIGN_ALIAS = "SERVER_SIGN_ENTRY";
    private final String CLIENT_ENC_ALIAS = "CLIENT_ENC_ENTRY";
    private final String CLIENT_SIGN_ALIAS = "CLIENT_SIGN_ENTRY";
    // root ca.
    private final String CA_CERT_PATH = "tlcp_cert/ca.crt";
    // sub ca.
    private final String SUB_CA_CERT_PATH = "tlcp_cert/sub_ca.crt";
    // client enc cert and key.
    private final String CLIENT_ENC_KEY_PATH = "tlcp_cert/client_enc.key";
    private final String CLIENT_ENC_CERT_PATH = "tlcp_cert/client_enc.crt";
    // client sign cert and key.
    private final String CLIENT_SIGN_KEY_PATH = "tlcp_cert/client_sign.key";
    private final String CLIENT_SIGN_CERT_PATH = "tlcp_cert/client_sign.crt";
    // server enc cert and key.
    private final String SERVER_ENC_KEY_PATH = "tlcp_cert/server_enc.key";
    private final String SERVER_ENC_CERT_PATH = "tlcp_cert/server_enc.crt";
    // server sign cert and key.
    private final String SERVER_SIGN_KEY_PATH = "tlcp_cert/server_sign.key";
    private final String SERVER_SIGN_CERT_PATH = "tlcp_cert/server_sign.crt";

    private static final String HELLO_REQUEST = "hello request";
    private static final String HELLO_RESPONSE = "hello response";

    private volatile int port = -1;

    private final char[] EMPTY_PASSWORD = new char[0];

    private X509Certificate caCert;
    private X509Certificate subCaCert;

    private X509Certificate clientSignCert;
    private X509Certificate clientEncCert;
    private PrivateKey clientSignPrivateKey;
    private PrivateKey clientEncPrivateKey;

    private X509Certificate serverSignCert;
    private X509Certificate serverEncCert;
    private PrivateKey serverSignPrivateKey;
    private PrivateKey serverEncPrivateKey;

    private KeyManager[] clientKeyManager;
    private TrustManager[] clientTrustManager;
    private KeyManager[] serverKeyManager;
    private TrustManager[] serverTrustManager;

    private CountDownLatch downLatch = new CountDownLatch(1);

    @Before
    public final void before() throws Exception {
        // Initial cipher suit map.
        CIPHER_SUIT_MAP.put("ECC-SM2-WITH-SM4-SM3", "ECC-SM2-SM4-CBC-SM3");
        CIPHER_SUIT_MAP.put("ECC-SM2-SM4-CBC-SM3", "ECC-SM2-SM4-CBC-SM3");
        CIPHER_SUIT_MAP.put("ECC-SM2-SM4-GCM-SM3", "ECC-SM2-SM4-GCM-SM3");
        CIPHER_SUIT_MAP.put("ECDHE-SM2-WITH-SM4-SM3", "ECDHE-SM2-SM4-CBC-SM3");
        CIPHER_SUIT_MAP.put("ECDHE-SM2-SM4-CBC-SM3", "ECDHE-SM2-SM4-CBC-SM3");
        CIPHER_SUIT_MAP.put("ECDHE-SM2-SM4-GCM-SM3", "ECDHE-SM2-SM4-GCM-SM3");

        Security.addProvider(new TongsuoProvider());

        buildCaCert();
        buildClientKeyStore();
        buildServerKeyStore();
    }

    @After
    public final void after() {
    }

    private void buildCaCert() throws Exception {
        caCert = OpenSSLX509Certificate.fromX509PemInputStream(TestUtils.openTestFile(CA_CERT_PATH));
        subCaCert = OpenSSLX509Certificate.fromX509PemInputStream(TestUtils.openTestFile(SUB_CA_CERT_PATH));
    }

    private void buildClientKeyStore() throws Exception {
        // build client private key.
        clientSignPrivateKey = TestUtils.readSM2PrivateKeyPemFile(CLIENT_SIGN_KEY_PATH);
        clientEncPrivateKey = TestUtils.readSM2PrivateKeyPemFile(CLIENT_ENC_KEY_PATH);
        // build client sign and enc certification.
        clientSignCert = OpenSSLX509Certificate.fromX509PemInputStream(TestUtils.openTestFile(CLIENT_SIGN_CERT_PATH));
        clientEncCert = OpenSSLX509Certificate.fromX509PemInputStream(TestUtils.openTestFile(CLIENT_ENC_CERT_PATH));

        X509Certificate[] clientSignCertChain = new X509Certificate[]{clientSignCert, subCaCert, caCert};
        X509Certificate[] clientEncCertChain = new X509Certificate[]{clientEncCert, subCaCert, caCert};

        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null);
        ks.setKeyEntry(CLIENT_ENC_ALIAS, clientEncPrivateKey, EMPTY_PASSWORD, clientEncCertChain);
        ks.setKeyEntry(CLIENT_SIGN_ALIAS, clientSignPrivateKey, EMPTY_PASSWORD, clientSignCertChain);
        ks.setCertificateEntry("CA", caCert);
        ks.setCertificateEntry("SUB_CA", subCaCert);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("TlcpKeyManagerFactory", new TongsuoProvider());
        kmf.init(ks, EMPTY_PASSWORD);
        KeyManager clientKey = kmf.getKeyManagers()[0];
        if (clientKey instanceof TlcpKeyManagerImpl) {
            TlcpKeyManagerImpl tlcpKeyManager = (TlcpKeyManagerImpl) clientKey;
            clientKeyManager = new KeyManager[]{clientKey};
            tlcpKeyManager.setTlcpEncAlias(CLIENT_ENC_ALIAS);
            tlcpKeyManager.setTlcpSignAlias(CLIENT_SIGN_ALIAS);
        } else {
            assertTrue(false);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        clientTrustManager = tmf.getTrustManagers();
        assertEquals(clientTrustManager.length, 1);
    }

    private void buildServerKeyStore() throws Exception {
        // build server private key.
        serverSignPrivateKey = TestUtils.readSM2PrivateKeyPemFile(SERVER_SIGN_KEY_PATH);
        serverEncPrivateKey = TestUtils.readSM2PrivateKeyPemFile(SERVER_ENC_KEY_PATH);
        // build server sign and enc certification.
        serverSignCert = OpenSSLX509Certificate.fromX509PemInputStream(TestUtils.openTestFile(SERVER_SIGN_CERT_PATH));
        serverEncCert = OpenSSLX509Certificate.fromX509PemInputStream(TestUtils.openTestFile(SERVER_ENC_CERT_PATH));

        X509Certificate[] serverSignCertChain = new X509Certificate[]{serverSignCert, subCaCert, caCert};
        X509Certificate[] serverEncCertChain = new X509Certificate[]{serverEncCert, subCaCert, caCert};

        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null);
        ks.setKeyEntry(SERVER_ENC_ALIAS, serverEncPrivateKey, EMPTY_PASSWORD, serverEncCertChain);
        ks.setKeyEntry(SERVER_SIGN_ALIAS, serverSignPrivateKey, EMPTY_PASSWORD, serverSignCertChain);
        ks.setCertificateEntry("CA", caCert);
        ks.setCertificateEntry("SUB_CA", subCaCert);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("TlcpKeyManagerFactory", new TongsuoProvider());
        kmf.init(ks, EMPTY_PASSWORD);
        KeyManager serverKey = kmf.getKeyManagers()[0];
        if (serverKey instanceof TlcpKeyManagerImpl) {
            TlcpKeyManagerImpl tlcpKeyManager = (TlcpKeyManagerImpl) serverKey;
            serverKeyManager = new KeyManager[]{serverKey};
            tlcpKeyManager.setTlcpEncAlias(SERVER_ENC_ALIAS);
            tlcpKeyManager.setTlcpSignAlias(SERVER_SIGN_ALIAS);
        } else {
            assertTrue(false);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        serverTrustManager = tmf.getTrustManagers();
        assertEquals(serverTrustManager.length, 1);
    }

    private SSLServerSocket buildSSLServerSocket(String[] ciphers) throws Exception {
        SSLContext sslContext = SSLContext.getInstance(TLCP, new TongsuoProvider());
        assertTrue(sslContext.getProtocol().equals("TLCP"));
        sslContext.init(serverKeyManager, serverTrustManager, new SecureRandom());
        SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();
        SSLServerSocket svrSocket = (SSLServerSocket) serverFactory.createServerSocket(0);
        port = svrSocket.getLocalPort();
        if (ciphers != null) {
            svrSocket.setEnabledCipherSuites(ciphers);
        }
        svrSocket.setNeedClientAuth(true);
        return svrSocket;
    }

    private SSLSocket buildSSLClientSocket(String[] ciphers, boolean setEnableCipher) throws Exception {
        SSLContext sslContext = SSLContext.getInstance(TLCP, new TongsuoProvider());
        sslContext.init(clientKeyManager, clientTrustManager, new SecureRandom());
        SSLSocketFactory sslCntFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslCntFactory.createSocket("localhost", port);
        if (ciphers != null && setEnableCipher) {
            sslSocket.setEnabledCipherSuites(ciphers);
        }
        return sslSocket;
    }

    private void startServer(String[] ciphers) throws Exception {
        // Start server asynchronously.
        SSLServerSocket serverSocket = buildSSLServerSocket(ciphers);
        Thread serverThread = new Thread(() -> {
            try {
                downLatch.countDown();
                for (int i = 0; i < CIPHER_SUIT_MAP.size(); i++) {
                    SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
                    BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));
                    String tmpMsg = ioReader.readLine();
                    if (tmpMsg != null) {
                        assertEquals(tmpMsg, HELLO_REQUEST);
                        ioWriter.println(HELLO_RESPONSE);
                        ioWriter.flush();
                        Thread.sleep(1_000);
                    }
                }
            } catch (Exception e) {
                assertTrue(false);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void startClient(String[] ciphers, boolean setEnableCipher) throws Exception {
        downLatch.await();
        // Wait for server startup.
        Thread.sleep(2_000);
        for (String key : ciphers) {
            SSLSocket clientSocket0 = buildSSLClientSocket(new String[]{key}, setEnableCipher);
            BufferedReader ioReader = new BufferedReader(new InputStreamReader(
                    clientSocket0.getInputStream(), StandardCharsets.UTF_8));
            PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket0.getOutputStream(), StandardCharsets.UTF_8)));
            ioWriter.println(HELLO_REQUEST);
            ioWriter.flush();
            assertEquals(ioReader.readLine(), HELLO_RESPONSE);
            assertEquals(clientSocket0.getSession().getCipherSuite(), CIPHER_SUIT_MAP.get(key));
            clientSocket0.close();
        }
    }

    private void startSessionResumptionServer() throws Exception {
        SSLContext sslContext = SSLContext.getInstance(TLCP, new TongsuoProvider());
        assertTrue(sslContext.getProtocol().equals("TLCP"));
        sslContext.init(serverKeyManager, serverTrustManager, new SecureRandom());
        SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();
        SSLServerSocket svrSocket = (SSLServerSocket) serverFactory.createServerSocket(0);
        port = svrSocket.getLocalPort();
        svrSocket.setNeedClientAuth(true);
        svrSocket.setEnableSessionCreation(true);

        Thread serverThread = new Thread(() -> {
            try {
                downLatch.countDown();
                for (int i = 0x0; i < 2; i++) {
                    SSLSocket sslSocket = (SSLSocket) svrSocket.accept();
                    BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));
                    String tmpMsg = ioReader.readLine();
                    if (tmpMsg != null) {
                        assertEquals(tmpMsg, HELLO_REQUEST);
                        ioWriter.println(HELLO_RESPONSE);
                        ioWriter.flush();
                        Thread.sleep(1_000);
                    }
                }
            } catch (Exception e) {
                assertTrue(false);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void startSessionResumptionClient() throws Exception {
        SSLContext sslContext = SSLContext.getInstance(TLCP, new TongsuoProvider());
        sslContext.init(clientKeyManager, clientTrustManager, new SecureRandom());
        SSLSocketFactory sslCntFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslCntFactory.createSocket("localhost", port);

        downLatch.await();
        // Wait for server startup.
        Thread.sleep(2_000);
        BufferedReader ioReader = new BufferedReader(new InputStreamReader(
                sslSocket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));
        ioWriter.println(HELLO_REQUEST);
        ioWriter.flush();
        assertEquals(ioReader.readLine(), HELLO_RESPONSE);
        String sessionID = new String(sslSocket.getSession().getId(), StandardCharsets.UTF_8);
        Thread.sleep(2_000);
        sslSocket.close();

        SSLSocket sslSocket0 = (SSLSocket) sslCntFactory.createSocket("localhost", port);
        ioReader = new BufferedReader(new InputStreamReader(
                sslSocket0.getInputStream(), StandardCharsets.UTF_8));
        ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket0.getOutputStream(), StandardCharsets.UTF_8)));
        ioWriter.println(HELLO_REQUEST);
        ioWriter.flush();
        assertEquals(ioReader.readLine(), HELLO_RESPONSE);
        assertEquals(sessionID, new String(sslSocket0.getSession().getId(), StandardCharsets.UTF_8));
        Thread.sleep(2_000);
        sslSocket.close();
    }

    @Test
    public void testTlcpSocket() throws Exception {
        startServer(null);
        startClient(CIPHER_SUIT_MAP.keySet().toArray(new String[0]), true);
    }

    @Test
    public void testTlcpCipherNegotiate() throws Exception {
        for (String cipher : CIPHER_SUIT_MAP.keySet().toArray(new String[0])) {
            downLatch = new CountDownLatch(1);
            startServer(new String[]{cipher});
            startClient(new String[]{cipher}, false);
        }
    }

    @Test
    public void testSessionResumption() throws Exception {
        downLatch = new CountDownLatch(1);
        startSessionResumptionServer();
        startSessionResumptionClient();
    }

    @Test
    public void testTlcpCertSNIAndAlpn() throws Exception {
        downLatch = new CountDownLatch(1);
        SSLContext sslContextServer = SSLContext.getInstance(TLCP, new TongsuoProvider());
        assertTrue(sslContextServer.getProtocol().equals("TLCP"));
        sslContextServer.init(serverKeyManager, serverTrustManager, new SecureRandom());
        SSLServerSocketFactory serverFactory = sslContextServer.getServerSocketFactory();
        SSLServerSocket svrSocket = (SSLServerSocket) serverFactory.createServerSocket(0);
        port = svrSocket.getLocalPort();

        Thread serverThread = new Thread(() -> {
            try {
                downLatch.countDown();
                for (int i = 0x0; i < 1; i++) {
                    SSLSocket sslSocket = (SSLSocket) svrSocket.accept();
                    Conscrypt.setApplicationProtocols(sslSocket, new String[] {HTTP_2});
                    BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));
                    SSLSession session = (SSLSession) sslSocket.getClass().getSuperclass().getDeclaredMethod("getActiveSession").invoke(sslSocket);
                    String hostname = (String) session.getClass().getMethod("getRequestedServerName").invoke(session);
                    assertEquals(hostname, SNI_HOST_NAME);
                    String tmpMsg = ioReader.readLine();
                    if (tmpMsg != null) {
                        assertEquals(tmpMsg, HELLO_REQUEST);
                        ioWriter.println(HELLO_RESPONSE);
                        ioWriter.flush();
                        Thread.sleep(1_000);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                assertTrue(false);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        SSLContext sslContextClient = SSLContext.getInstance(TLCP, new TongsuoProvider());
        sslContextClient.init(clientKeyManager, clientTrustManager, new SecureRandom());
        SSLSocketFactory sslCntFactory = sslContextClient.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslCntFactory.createSocket("localhost", port);
        Conscrypt.setHostname(sslSocket, SNI_HOST_NAME);
        Conscrypt.setApplicationProtocols(sslSocket, new String[] {HTTP_1_1, HTTP_2});

        downLatch.await();
        // Wait for server startup.
        Thread.sleep(2_000);
        BufferedReader ioReader = new BufferedReader(new InputStreamReader(
                sslSocket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));
        ioWriter.println(HELLO_REQUEST);
        ioWriter.flush();
        assertEquals(ioReader.readLine(), HELLO_RESPONSE);
        assertEquals(Conscrypt.getApplicationProtocol(sslSocket), HTTP_2);
        Thread.sleep(2_000);
        sslSocket.close();
    }
}
