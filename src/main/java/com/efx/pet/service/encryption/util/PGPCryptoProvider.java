package com.efx.pet.service.encryption.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;


public class PGPCryptoProvider {
    private static final AtomicBoolean isRegistered = new AtomicBoolean();

    private PGPCryptoProvider() {}

    public static synchronized void register() {
        if (isRegistered.compareAndSet(false, true)) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
