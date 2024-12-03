package org.tomaszewski.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.List;

public class MyRemoteKeyStore {
    private final KeyStore ks;
    private final PrivateKey privateKey;
    private final List<String> certUrlList;

    public MyRemoteKeyStore(InputStream stream, char[] password, String KeyStoreType, List<String> remoteCertificateList) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        try (stream){
            this.certUrlList = remoteCertificateList;
            this.ks = KeyStore.getInstance(KeyStoreType);
            ks.load(stream, password);
            this.privateKey = (PrivateKey) ks.getKey(ks.aliases().nextElement(), password);
        }
    }

    public List<String> getCertUrlList() {
        return this.certUrlList;
    }

    public KeyStore getKeyStore() {
        return this.ks;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
