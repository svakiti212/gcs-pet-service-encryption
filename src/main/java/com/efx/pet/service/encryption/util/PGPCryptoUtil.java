package com.efx.pet.service.encryption.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class PGPCryptoUtil {


    static {
        PGPCryptoProvider.register();
    }

    /**
     * Decrypts the input PGP stream based on the privateKey and passPhrase and returns an String of decrypted data
     */
    public String decrypt(InputStream encryptedInputStream, InputStream keyInputStream, char[] passPhrase)
        throws IOException, PGPException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (
            InputStream io = getDecryptedInputStream(encryptedInputStream, keyInputStream, passPhrase);
            InputStream decompressedInputStream = decompress(io);
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream);
        ) {
            Streams.pipeAll(decompressedInputStream, bufferedOutputStream);
        }
        outputStream.close();
        return new String(outputStream.toByteArray());
    }

    private InputStream getDecryptedInputStream(InputStream encryptedInputStream, InputStream keyInputStream,
                                                       char[] passPhrase) throws IOException, PGPException {

        InputStream decoderEncryptedInputStream = PGPUtil.getDecoderStream(encryptedInputStream);
        InputStream decoderKeyInputStream = PGPUtil.getDecoderStream(keyInputStream);
        // decode the input stream
        JcaKeyFingerprintCalculator fingerprintCalculator = new JcaKeyFingerprintCalculator();
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(decoderKeyInputStream, fingerprintCalculator);
        //Get the encrypted objects
        List<PGPPublicKeyEncryptedData> pgpEncryptedDataObjects = getPgpEncryptedDataObjects(decoderEncryptedInputStream);
        PGPPublicKeyEncryptedData publicKeyEncryptedData = pgpEncryptedDataObjects.get(0);

        //find the secret key
        PGPPrivateKey secretKey = PGPSecretKeyHelper.findSecretKey(pgpSec, publicKeyEncryptedData.getKeyID(), passPhrase);
        //Get the decrypted stream
        PublicKeyDataDecryptorFactory decryptorFactory = (new JcePublicKeyDataDecryptorFactoryBuilder())
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(secretKey);

        return publicKeyEncryptedData.getDataStream(decryptorFactory);
    }

    private InputStream decompress(InputStream clear) throws IOException, PGPException {

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
        Object plainFactMessage = plainFact.nextObject();
        JcaPGPObjectFactory pgpFact = null;
        // Decompress if it is compressed
        if (plainFactMessage instanceof PGPCompressedData) {
            PGPCompressedData compressedData = (PGPCompressedData) plainFactMessage;
            InputStream compressedStream = new BufferedInputStream(compressedData.getDataStream());
            pgpFact = new JcaPGPObjectFactory(compressedStream);
            plainFactMessage = pgpFact.nextObject();
        }
        // Build the stream
        if (plainFactMessage instanceof PGPLiteralData) {
            return ((PGPLiteralData) plainFactMessage).getInputStream();
        } else if (plainFactMessage instanceof PGPOnePassSignatureList) {
            PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) plainFactMessage;
            p1.get(0);
            PGPLiteralData p2 = (PGPLiteralData) plainFact.nextObject();
            return p2.getInputStream();
        } else {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }
    }

    private PGPEncryptedDataList getPgpEncryptedDataList(InputStream decoderInputStream) throws IOException {
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(decoderInputStream);
        Object obj = pgpObjectFactory.nextObject();
        // the first object might be a PGP marker packet.
        if (obj instanceof PGPEncryptedDataList) {
            return (PGPEncryptedDataList) obj;
        } else {
            return (PGPEncryptedDataList) pgpObjectFactory.nextObject();
        }
    }

    private List<PGPPublicKeyEncryptedData> getPgpEncryptedDataObjects(InputStream decoderInputStream)
        throws IOException {
        PGPEncryptedDataList pgpEncryptedDataList = getPgpEncryptedDataList(decoderInputStream);

        Iterator<?> encryptedDataObjects = pgpEncryptedDataList.getEncryptedDataObjects();

        return Collections.singletonList((PGPPublicKeyEncryptedData) encryptedDataObjects.next());
    }
}