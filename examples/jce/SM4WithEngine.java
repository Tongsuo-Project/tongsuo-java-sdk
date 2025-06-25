/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

import java.security.SecureRandom;
import java.security.Security;
import java.security.AlgorithmParameters;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import net.tongsuo.TongsuoProvider;

public class SM4WithEngine {
    public static void main(String[] args) throws Exception {
        TongsuoProvider ts = new TongsuoProvider();
        if (ts.setEngine("hct") != 1) {
            System.out.println("set engine failed");
            return;
        }
        Security.addProvider(ts);

        byte[] msg = "Hello SM4-CBC!".getBytes();
        SecureRandom random = new SecureRandom();
        int testLen = 32;
        if(args.length > 0)
        {
           try{
               testLen = Integer.parseInt(args[0]);
               testLen = (testLen + 15) / 16 * 16;
           } catch (NumberFormatException e)
           {
               System.out.println("Invalid input length");
           }
        }
        // input padding
        System.out.println("Test SM4 data length: " + testLen);
        byte[] mess = new byte[testLen];
        random.nextBytes(mess);
        System.arraycopy(msg, 0, mess, 0, Math.min(msg.length, 16));

        // algorithm/mode/padding
        Cipher cipher = Cipher.getInstance("SM4/CBC/NoPadding", "Tongsuo_Security_Provider");
        byte[] key = new byte[16];
        random.nextBytes(key);
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        SecretKeySpec secretKey =  new SecretKeySpec(key, "SM4");
        // Initialize the IV
        AlgorithmParameters params = AlgorithmParameters.getInstance("SM4");
        params.init(iv, "RAW");
        // init cipher in encryption mode
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, params);

        byte[] ciphertext = cipher.doFinal(mess);

        // init cipher in decryption mode
        cipher.init(Cipher.DECRYPT_MODE, secretKey, params);
        byte[] decrypted = cipher.doFinal(ciphertext);

        // decrypted text should be identical to input
        System.out.println(Base64.getEncoder().encodeToString(mess));
        System.out.println(Base64.getEncoder().encodeToString(decrypted));
    }
}
