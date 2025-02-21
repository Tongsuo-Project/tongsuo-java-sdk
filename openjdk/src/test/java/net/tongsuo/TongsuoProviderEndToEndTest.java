/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package net.tongsuo;

import javax.net.ssl.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.concurrent.CountDownLatch;

import net.tongsuo.TongsuoX509Certificate;
import net.tongsuo.TongsuoProvider;

import org.junit.Test;

import static org.conscrypt.TestUtils.openTestFile;
import static org.conscrypt.TestUtils.readSM2PrivateKeyPemFile;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class TongsuoProviderEndToEndTest {
    private static final char[] EMPTY_PASSWORD = new char[0];
    private static final String SSL_13_TYPE = "TLSv1.3";
    private static final String SERVER_CA = "cert/sm2-root.crt";
    private static final String PRIVATE_KEY = "cert/sm2-root.key";
    private static final String CIPHER_SUITE = "TLS_SM4_GCM_SM3";
    private static final String HELLO_REQUEST = "hello request";
    private static final String HELLO_RESPONSE = "hello response";

    private volatile int port = -1;

    static {
        Security.addProvider(new TongsuoProvider());
    }

    private SSLContext createServerSSLContext() throws Exception {
        // Create an empty keystore
        KeyStore ks = KeyStore.getInstance("PKCS12", new TongsuoProvider());
        ks.load(null, null);

        // Build a service CA
        X509Certificate ca = TongsuoX509Certificate.fromX509PemInputStream(openTestFile(SERVER_CA));
        PrivateKey privateKey = readSM2PrivateKeyPemFile(PRIVATE_KEY);

        ks.setKeyEntry("default", privateKey, EMPTY_PASSWORD, new X509Certificate[]{ca});
        ks.setCertificateEntry("CA", ca);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] tms = tmf.getTrustManagers();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, EMPTY_PASSWORD);
        KeyManager[] kms = kmf.getKeyManagers();

        SSLContext sslContext = SSLContext.getInstance(SSL_13_TYPE, new TongsuoProvider());
        sslContext.init(kms, tms, new SecureRandom());
        return sslContext;
    }

    private SSLServerSocket buildSSLServerSocket(SSLContext serverContext) throws Exception {
        SSLServerSocketFactory serverFactory = serverContext.getServerSocketFactory();
        SSLServerSocket svrSocket = (SSLServerSocket) serverFactory.createServerSocket(0);
        port = svrSocket.getLocalPort();
        svrSocket.setNeedClientAuth(false);
        return svrSocket;
    }

    private SSLContext createClientSSLContext() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", new TongsuoProvider());
        ks.load(null, null);

        X509Certificate ca = TongsuoX509Certificate
                .fromX509PemInputStream(openTestFile(SERVER_CA));
        ks.setCertificateEntry("CA", ca);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] tms = tmf.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance(SSL_13_TYPE, new TongsuoProvider());
        sslContext.init(null, tms, new SecureRandom());
        return sslContext;
    }

    private SSLSocket buildSSLClientSocket(SSLContext clientContext) throws Exception {
        SSLSocketFactory sslCntFactory = clientContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslCntFactory.createSocket("localhost", port);
        sslSocket.setEnabledCipherSuites(new String[]{CIPHER_SUITE});
        return sslSocket;
    }

    @Test
    public void testTongsuoProvider() throws Exception {
        CountDownLatch downLatch = new CountDownLatch(1);

        // Start server asynchronously.
        SSLServerSocket serverSocket = buildSSLServerSocket(createServerSSLContext());
        Thread serverThread = new Thread(() -> {
            try {
                downLatch.countDown();
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
                BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream(), StandardCharsets.UTF_8)));
                String tmpMsg = ioReader.readLine();
                if (tmpMsg != null) {
                    assertEquals(tmpMsg, HELLO_REQUEST);
                    ioWriter.println(HELLO_RESPONSE);
                    ioWriter.flush();
                    assertEquals(sslSocket.getSession().getCipherSuite(), CIPHER_SUITE);
                    Thread.sleep(1_000);
                }
            } catch (Exception e) {
                assertTrue(false);
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        // Start client.
        downLatch.await();
        // Wait for server startup.
        Thread.sleep(2_000);
        SSLSocket clientSocket = buildSSLClientSocket(createClientSSLContext());
        BufferedReader ioReader = new BufferedReader(new InputStreamReader(
                clientSocket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter ioWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8)));
        ioWriter.println(HELLO_REQUEST);
        ioWriter.flush();
        assertEquals(ioReader.readLine(), HELLO_RESPONSE);
        clientSocket.close();
    }
}
