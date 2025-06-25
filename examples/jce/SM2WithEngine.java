/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import net.tongsuo.TongsuoProvider;

public class SM2WithEngine {
    static {
        // install tongsuo provider
        TongsuoProvider ts = new TongsuoProvider();
        if (ts.setEngine("hct") != 1) {
            System.out.println("set engine failed");
        }
        Security.addProvider(ts);
    }

    public static void main(String[] args) throws Exception {
        byte[] mess = "example".getBytes();

        // SM3withSM2 requires SM2 key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "Tongsuo_Security_Provider");
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        Signature sig = Signature.getInstance("SM3withSM2", "Tongsuo_Security_Provider");
        // sign using private key
        sig.initSign(privateKey);
        // feed in mess(s)
        sig.update(mess);
        // genereate signatrue
        byte[] signature = sig.sign();

        // verify using public key
        sig.initVerify(publicKey);
        // same mess(s) as in signing procedure
        sig.update(mess);
        // return true if signature is genuine
        System.out.println(sig.verify(signature));
    }
}
