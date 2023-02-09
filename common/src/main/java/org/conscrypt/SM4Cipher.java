/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import javax.crypto.NoSuchPaddingException;

@Internal
public class SM4Cipher extends OpenSSLEvpCipher {
    private static final int SM4_BLOCK_SIZE = 16;
    private static final int SM4_KEY_SIZE = 16;

    SM4Cipher(Mode mode, Padding padding) {
        super(mode, padding);
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        switch (mode) {
            case CBC:
            case CTR:
            case ECB:
            case CFB:
            case OFB:
                return;
            default:
                throw new NoSuchAlgorithmException("Unsupported mode " + mode.toString());
        }
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        switch (padding) {
            case NOPADDING:
            case PKCS5PADDING:
                return;
            default:
                throw new NoSuchPaddingException(
                        "Unsupported padding " + padding.toString());
        }
    }

    @Override
    String getBaseCipherName() {
        return "SM4";
    }

    @Override
    String getCipherName(int keyLength, Mode mode) {
        return "sm4-" + mode.toString().toLowerCase(Locale.US);
    }

    @Override
    int getCipherBlockSize() {
        return SM4_BLOCK_SIZE;
    }

    @Override
    void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
        if (keyLength != SM4_KEY_SIZE) {
            throw new InvalidKeyException("Unsupported key size: " + keyLength
                + " bytes");
        }
    }

    public static class CBC extends SM4Cipher {
        CBC(Padding padding) {
            super(Mode.CBC, padding);
        }

        public static class NoPadding extends CBC {
            public NoPadding() {
                super(Padding.NOPADDING);
            }
        }

        public static class PKCS5Padding extends CBC {
            public PKCS5Padding() {
                super(Padding.PKCS5PADDING);
            }
        }
    }

    public static class CTR extends SM4Cipher {
        public CTR() {
            super(Mode.CTR, Padding.NOPADDING);
        }
    }

    public static class ECB extends SM4Cipher {
        ECB(Padding padding) {
            super(Mode.ECB, padding);
        }

        public static class NoPadding extends ECB {
            public NoPadding() {
                super(Padding.NOPADDING);
            }
        }

        public static class PKCS5Padding extends ECB {
            public PKCS5Padding() {
                super(Padding.PKCS5PADDING);
            }
        }
    }

    public static class CFB extends SM4Cipher {
        public CFB() {
            super(Mode.CFB, Padding.NOPADDING);
        }
    }

    public static class OFB extends SM4Cipher {
        public OFB() {
            super(Mode.OFB, Padding.NOPADDING);
        }
    }
}
