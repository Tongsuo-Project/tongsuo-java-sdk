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
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import net.tongsuo.TongsuoProvider;
import net.tongsuo.TongsuoX509Certificate;


public class TLS13Client {
    public static void main(String[] args)throws Exception{
        String ip = "127.0.0.1";
        int port = 443;
        String ciperSuites = "TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3";
        String caCert = "chain.crt";

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", new TongsuoProvider());

        X509Certificate ca = null;
        if(caCert != null && "".equals(caCert.trim())){
            ca = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(caCert)));
        }

        final X509Certificate caCertificate = ca;
        TrustManager[] tms = new TrustManager[] { new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException{
                if(caCertificate != null){
                    for (X509Certificate cert : certs) {
                        try {
                            cert.checkValidity();
                            cert.verify(caCertificate.getPublicKey());
                        } catch (Exception e) {
                            e.printStackTrace();
                            throw new CertificateException(e);
                        }
                    }
                }
            }
        }};

        sslContext.init(null, tms, new SecureRandom());
        System.out.println("Client SSL context init success...");

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket)socketFactory.createSocket(ip, port);

        if(ciperSuites != null && !"".equals(ciperSuites.trim())){
            String[] ciperSuiteArray = ciperSuites.split(":");
            sslSocket.setEnabledCipherSuites(ciperSuiteArray);
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
