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
import java.util.Collection;
import java.util.List;
import java.util.ArrayList;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateParsingException;

public class TLCPClient {
    public static void main(String[] args) throws Exception {
        String[] ciphers = { "ECC-SM2-SM4-GCM-SM3" };
        int port = 4433;
        String caCertFile = "ca.crt";
        String subCaCertFile = "subca.crt";
        X509Certificate caCert = TongsuoX509Certificate
                .fromX509PemInputStream(new FileInputStream(new File(caCertFile)));
        X509Certificate subCaCert = TongsuoX509Certificate
                .fromX509PemInputStream(new FileInputStream(new File(subCaCertFile)));

        TrustManager[] tms = new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] certs, String authType)
                            throws CertificateException {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType)
                            throws CertificateException {
                        if (subCaCert != null) {
                            for (X509Certificate cert : certs) {
                                try {
                                    cert.checkValidity();
                                    if (cert.getIssuerX500Principal().equals(subCaCert.getSubjectX500Principal())) {
                                        // verifyHostname(cert, "localhost");
                                        cert.verify(subCaCert.getPublicKey());
                                    } else if (cert.getIssuerX500Principal().equals(caCert.getSubjectX500Principal())) {
                                        cert.verify(caCert.getPublicKey());
                                    } else {
                                        throw new CertificateException("Certificate issuer does not match CA or SubCA");
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                    throw new CertificateException(e);
                                }
                            }
                        }
                    }

                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    void verifyHostname(X509Certificate cert, String hostname) throws CertificateException {
                        if (hostname == null || hostname.isEmpty()) {
                            throw new CertificateException("Hostname is empty");
                        }

                        List<String> possibleNames = getAllPossibleHostnames(cert);

                        for (String name : possibleNames) {
                            if (matchHostname(name, hostname)) {
                                return;
                            }
                        }

                        throw new CertificateException(
                                "No matching hostname found in certificate. Expected: " + hostname);
                    }

                    List<String> getAllPossibleHostnames(X509Certificate cert) throws CertificateException {
                        List<String> result = new ArrayList<>();

                        try {
                            X500Principal principal = cert.getSubjectX500Principal();
                            LdapName ldapName = new LdapName(principal.getName());

                            for (Rdn rdn : ldapName.getRdns()) {
                                if ("CN".equalsIgnoreCase(rdn.getType())) {
                                    result.add(rdn.getValue().toString());
                                }
                            }
                        } catch (Exception e) {
                            throw new CertificateException("Error extracting CN: " + e.getMessage());
                        }

                        try {
                            Collection<List<?>> subjectAltNames = cert.getSubjectAlternativeNames();
                            if (subjectAltNames != null) {
                                for (List<?> san : subjectAltNames) {
                                    if (san.size() >= 2) {
                                        Integer type = (Integer) san.get(0);
                                        if (type == 2) {
                                            String name = (String) san.get(1);
                                            result.add(name);
                                        }
                                    }
                                }
                            }
                        } catch (CertificateParsingException e) {
                            throw new CertificateException("Error extracting SAN: " + e.getMessage());
                        }

                        return result;
                    }

                    boolean matchHostname(String pattern, String hostname) {
                        if (pattern.equals(hostname)) {
                            return true;
                        }

                        if (pattern.startsWith("*.")) {
                            String suffix = pattern.substring(1);

                            if (hostname.length() > suffix.length()) {
                                if (hostname.endsWith(suffix)) {
                                    String prefix = hostname.substring(0, hostname.length() - suffix.length());
                                    return !prefix.contains(".");
                                }
                            }
                        }

                        return false;
                    }

                }
        };

        SSLContext sslContext = SSLContext.getInstance("TLCP", new TongsuoProvider());
        sslContext.init(null, tms, new SecureRandom());
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
        while ((line = bufferedReader.readLine()) != null) {
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
