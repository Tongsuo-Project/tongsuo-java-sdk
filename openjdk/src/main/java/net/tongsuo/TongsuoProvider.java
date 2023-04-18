/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package net.tongsuo;

import org.conscrypt.OpenSSLProvider;

public final class TongsuoProvider extends OpenSSLProvider {

    private static final String INFO = "Tongsuo JCA/JCE/JSSE Provider, supporting RFC 8998";

    static final String NAME = "Tongsuo_Security_Provider";

    private static final double VERSION_NUM = 1.0D;

    public TongsuoProvider() {
        super(NAME, VERSION_NUM, INFO);
        // Register TlcpKeyManagerFactoryImpl and TlcpKeyManagerImpl
        put("KeyManagerFactory.TlcpKeyManagerFactory", TlcpKeyManagerFactoryImpl.class.getName());
        // put("X509ExtendedKeyManager.TlcpKeyManager", TlcpKeyManagerImpl.class.getName());
        put("KeyStore.PKCS12", "net.tongsuo.sun.security.pkcs12.PKCS12KeyStore");
    }
}
