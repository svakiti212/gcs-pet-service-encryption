package com.efx.pet.service.encryption.impl;

import com.efx.pet.service.encryption.PGPService;
import com.efx.pet.service.encryption.util.PGPCryptoProvider;
import com.efx.pet.service.encryption.util.PGPCryptoUtil;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

public class PGPServiceImpl implements PGPService {

    private String passPhrase = "";

    private String privateKeyLocation = "US_BREACH_NONPROD_PRIVATE.asc";

    private String publicKeyLocation = "US_BREACH_NONPROD_PUBLIC.asc";

    static {
        PGPCryptoProvider.register();
    }

    public String encryptLine(String clearInput) throws IOException, PGPException {
        byte[] clearData = clearInput.getBytes(StandardCharsets.UTF_8);
        PGPPublicKey encKey = readPublicKey(publicKeyLocation);
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        if (true) {
            out = new ArmoredOutputStream(out);
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream cos = compressedDataGenerator.open(bOut);
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();

        OutputStream pOut = literalDataGenerator.open(cos, //Compressed out
            PGPLiteralData.UTF8, "name", clearData.length, new Date());
        pOut.write(clearData);

        pOut.close();

        literalDataGenerator.close();
        compressedDataGenerator.close();
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
            .setWithIntegrityPacket(true)
            .setSecureRandom(new SecureRandom()).setProvider(BouncyCastleProvider.PROVIDER_NAME));
        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(BouncyCastleProvider.PROVIDER_NAME));
        byte[] bytes = bOut.toByteArray();
        OutputStream cOUT = encryptedDataGenerator.open(out, bytes.length);
        cOUT.write(bytes);
        cOUT.close();
        out.close();
        return new String(encOut.toByteArray(), StandardCharsets.UTF_8);
    }

    public String decryptLine(String encryptedInput) throws IOException, PGPException {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        try {
            try (
                InputStream secretKeyStream = classloader.getResourceAsStream(privateKeyLocation);
                InputStream encryptedInputStream = new ByteArrayInputStream(encryptedInput.getBytes());
//                 InputStream secretKeyInputStream = new ByteArrayInputStream(privatKeyStream)
            ) {
                return new PGPCryptoUtil().decrypt(encryptedInputStream, secretKeyStream, passPhrase.toCharArray());
            }
        } catch (IOException | PGPException | NullPointerException e) {
            System.out.println("Decryption Line Failed");
            e.printStackTrace();
            throw e;
        }
    }

    private static PGPPublicKey readPublicKey(String keyLocation) throws IOException, PGPException {
//        InputStream publicEncryptionKeyStream = new FileInputStream(keyLocation);
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        InputStream publicEncryptionKeyStream = classloader.getResourceAsStream(keyLocation);
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicEncryptionKeyStream), new BcKeyFingerprintCalculator());

        Iterator<?> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator<?> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException(
            "Can't find encryption key in key ring.");
    }
}
