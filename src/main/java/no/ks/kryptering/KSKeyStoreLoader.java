package no.ks.kryptering;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@SuppressWarnings("WeakerAccess")
public class KSKeyStoreLoader {

    private KeyStore keystore;

    public KSKeyStoreLoader(String keystorePath, char[] password) {
        this(keystorePath, password, "JCEKS");
    }

    public KSKeyStoreLoader(String keystorePath, char[] password, String keystoreType) {
        try {
            InputStream keystoreStream;
            if (new File(keystorePath).exists()) {
                keystoreStream = new FileInputStream(keystorePath);
            } else {
                keystoreStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystorePath);
            }
            keystore = KeyStore.getInstance(keystoreType);
            keystore.load(keystoreStream, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public KeyStore getKeystore() {
        return keystore;
    }

    public PrivateKey getPrivateKey(String alias, char[] password) {
        try {
            return (PrivateKey) keystore.getKey(alias, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate getPublicKey(String alias) {
        try {
            return (X509Certificate) keystore.getCertificate(alias);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
