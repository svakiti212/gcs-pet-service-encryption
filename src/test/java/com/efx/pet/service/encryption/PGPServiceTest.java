package com.efx.pet.service.encryption;

import com.efx.pet.service.encryption.impl.PGPServiceImpl;
import com.efx.pet.service.encryption.util.URIEncoder;
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
        String clearMessage = "DREAMSTATE9663D";
        System.out.println("Starting encryption");

        String encMessage = service.encryptLine(clearMessage);

        System.out.println("Encryption finished. \n" + " Result:\n" + encMessage);
        System.out.println("Starting decryption");

        String decryptedMessage = service.decryptLine(encMessage);

        System.out.println("Decryption finished.\n" + "Result: " + decryptedMessage);
        Assert.assertEquals(clearMessage, decryptedMessage);

        System.out.println(formatURL(URIEncoder.encodeURI(encMessage)));
    }
    @Test
    public void decrypt() throws IOException, PGPException {
        String encMessage = "";
        System.out.println("Starting decryption");
        String decryptedMessage = service.decryptLine(encMessage);

        System.out.println("Decryption finished.\n" + "Result: " + decryptedMessage);
    }

    private String formatURL(String encodedOfferCode){
        return String.format("https://int-my.equifax.com/consumer-registration/rest/1.0/redirectPartnerTenant?offerCode=%s&offerType=BREACH&lang=EN", encodedOfferCode);
    }


}
