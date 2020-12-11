package com.efx.pet.service.encryption;

import com.efx.pet.service.encryption.impl.PGPServiceImpl;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

public class PGPServiceTest {

    private PGPService service;

    @Before
    public void init() {
        service = new PGPServiceImpl();
    }

    @Test
    public void PGPTest() throws IOException, PGPException {
        String clearMessage = "TestValue";
        System.out.println("Starting encryption");

        String encMessage = service.encryptLine(clearMessage);

        System.out.println("Encryption finished. \n" + " Result:\n" + encMessage);
        System.out.println("Starting decryption");

        String decryptedMessage = service.decryptLine(encMessage);

        System.out.println("Decryption finished.\n" + "Result: " + decryptedMessage);
        Assert.assertEquals(clearMessage, decryptedMessage);
    }

}
