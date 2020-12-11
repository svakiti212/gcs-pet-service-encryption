package com.efx.pet.service.encryption.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public class PGPSecretKeyHelper {
    static {
        PGPCryptoProvider.register();
    }

    /**
     * Find the secret key from the key ring
     *
     * @param pgpSec keyring collection
     * @param keyID  identifier for the key
     * @param pass   for the key
     * @return private key for the associated key
     */
    public static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass) throws PGPException {
        PGPSecretKey pgpSecretKey = pgpSec.getSecretKey(keyID);
        if (pgpSecretKey == null) {
            throw new IllegalArgumentException("Secret key for message not found");
        }
        return pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pass));
    }
}
