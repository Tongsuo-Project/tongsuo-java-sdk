/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import net.tongsuo.TongsuoProvider;
import net.tongsuo.TongsuoX509Certificate;
import java.util.Base64;

public class TLS13Server {
    public static void main(String[] args)throws Exception{
        String ciperSuites = "TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3";
        String caCert = "chain.crt";
        String cert = "sm2.crt";
        String certKey = "sm2.key";
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", new TongsuoProvider());
        char[] EMPTY_PASSWORD = new char[0];
        X509Certificate ca = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(caCert)));
        X509Certificate crtCert = TongsuoX509Certificate.fromX509PemInputStream(new FileInputStream(new File(cert)));
        PrivateKey privateKey = readSM2PrivateKeyPemFile(certKey);

        X509Certificate[] chain = new X509Certificate[] {crtCert, ca};
        KeyStore ks = KeyStore.getInstance("PKCS12",new BouncyCastleProvider());
        ks.load(null);
        ks.setKeyEntry("cnnic", privateKey, EMPTY_PASSWORD, chain);
        ks.setCertificateEntry("CA", ca);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, EMPTY_PASSWORD);
        KeyManager[] kms = kmf.getKeyManagers();

        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        TrustManager[] tms = tmf.getTrustManagers();

         sslContext.init(kms, tms, new SecureRandom());
         System.out.println("Server SSL context init success...");

        SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket)socketFactory.createServerSocket(443);

        if(ciperSuites != null && !"".equals(ciperSuites.trim())){
            String[] ciperSuiteArray = ciperSuites.split(":");
            serverSocket.setEnabledCipherSuites(ciperSuiteArray);
        }

        String [] tlsVersion = new String[1];
        tlsVersion [0] = "TLSv1.3";
        serverSocket.setEnabledProtocols(tlsVersion);

        while (true){
            SSLSocket sslSocket = (SSLSocket)serverSocket.accept();

            try {
                BufferedReader in = new BufferedReader( new InputStreamReader(sslSocket.getInputStream()) );
                BufferedWriter out = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
                String msg = null;
                char[] cbuf = new char[1024];
                int len = 0;
                while((len = in.read(cbuf, 0, 1024)) != -1 ){
                    msg = new String(cbuf, 0, len);
                    out.write(msg);
                    out.flush();

                    if("Bye".equals(msg)) {
                         break;
                    }
                    System.out.printf("Received Message --> %s \n", msg);
                }
            } catch (IOException e){
                 e.printStackTrace();
            }
        }
     }

    public static PrivateKey readSM2PrivateKeyPemFile(String name)throws Exception{
        InputStreamReader inputStreamReader = new InputStreamReader(new FileInputStream(new File(name)), StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        StringBuilder sb = new StringBuilder();
        String line = null;
            while ((line = bufferedReader.readLine()) != null){
            if(line.startsWith("-")){
                continue;
            }
            sb.append(line).append("\n");
        }
        String ecKey = sb.toString().replaceAll("\\r\\n|\\r|\\n", "");
        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] keyByte = base64Decoder.decode(ecKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(eks2);
            return privateKey;
    }
}