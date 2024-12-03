/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

import java.security.MessageDigest;
import java.security.Security;
import java.util.Base64;
import net.tongsuo.TongsuoProvider;

public class SM3WithEngine {
    public static void main(String[] args) throws Exception {
        TongsuoProvider ts = new TongsuoProvider();
        if (ts.setEngine("hct") != 1) {
            System.out.println("set engine failed");
            return;
        }
        Security.addProvider(ts);

        byte[] buf = "hello world".getBytes();

        MessageDigest md = MessageDigest.getInstance("SM3", "Tongsuo_Security_Provider");
        md.update(buf);
        byte[] res = md.digest();

        System.out.println(Base64.getEncoder().encodeToString(res));
    }
}