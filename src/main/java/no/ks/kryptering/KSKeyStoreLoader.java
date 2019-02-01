package no.ks.kryptering;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KSKeyStoreLoader {

    private KeyStore keystore;

    public KSKeyStoreLoader(String keystorefile, String storepassword) {
        InputStream keystoreStream = null;
        try {
            if(new File(keystorefile).exists())
                keystoreStream = new FileInputStream(keystorefile);
            else {
                keystoreStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystorefile);
            }
            keystore = KeyStore.getInstance("JCEKS");
            keystore.load(keystoreStream, storepassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public KSKeyStoreLoader(String keystorefile, String storepassword, String keystoreType) {
        InputStream keystoreStream = null;
        try {
            if(new File(keystorefile).exists())
                keystoreStream = new FileInputStream(keystorefile);
            else {
                keystoreStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystorefile);
            }
            keystore = KeyStore.getInstance(keystoreType);
            keystore.load(keystoreStream, storepassword.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public KeyStore getKeystore() {
        return keystore;
    }

    public PrivateKey getPrivateKey(String alias, String password){
        try {
            return (PrivateKey) keystore.getKey(alias, password.toCharArray());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate getPublicKey(String alias){
        try {
            return (X509Certificate) keystore.getCertificate(alias);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
