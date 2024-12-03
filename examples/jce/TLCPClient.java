/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.security.KeyStore;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import net.tongsuo.TongsuoProvider;
import net.tongsuo.TongsuoX509Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.net.ssl.TrustManagerFactory;

public class TLCPClient {
    public static void main(String[] args) throws Exception {
        String[] ciphers = {"ECC-SM2-SM4-GCM-SM3"};
        int port = 4433;
        String caCertFile = "ca.crt";
        String subCaCertFile = "subca.crt";
        X509Certificate caCert = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(caCertFile)));
        X509Certificate subCaCert = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(subCaCertFile)));

        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null);
        ks.setCertificateEntry("CA", caCert);
        ks.setCertificateEntry("SUB_CA", subCaCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] clientTrustManager = tmf.getTrustManagers();

        SSLContext sslContext = SSLContext.getInstance("TLCP", new TongsuoProvider());
        sslContext.init(null, clientTrustManager, new SecureRandom());
        SSLSocketFactory sslCntFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslCntFactory.createSocket("localhost", port);
        if (ciphers != null) {
            sslSocket.setEnabledCipherSuites(ciphers);
        }

        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
        out.write("GET / HTTP/1.0\r\n\r\n");
        out.flush();

        System.out.println("client ssl send msessage success...");

        BufferedInputStream streamReader = new BufferedInputStream(sslSocket.getInputStream());
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(streamReader, "utf-8"));
        String line = null;
        while((line = bufferedReader.readLine())!= null){
            System.out.println("client receive server data:" + line);
        }

        while (true) {
            try {
                sslSocket.sendUrgentData(0xFF);
                Thread.sleep(1000L);
                System.out.println("client waiting server close");
            } catch (Exception e) {
                bufferedReader.close();
                out.close();
                sslSocket.close();
            }
        }
    }
}
