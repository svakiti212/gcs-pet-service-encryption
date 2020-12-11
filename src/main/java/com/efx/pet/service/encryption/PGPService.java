package com.efx.pet.service.encryption;

import org.bouncycastle.openpgp.PGPException;

import java.io.IOException;

public interface PGPService {

    String encryptLine(String clearData) throws IOException, PGPException;

    String decryptLine(String encryptedInput) throws IOException, PGPException;

}
