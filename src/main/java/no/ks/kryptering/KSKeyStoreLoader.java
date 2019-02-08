package no.ks.kryptering;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@SuppressWarnings("WeakerAccess")
public class KSKeyStoreLoader {

    private static final Logger log = LoggerFactory.getLogger(KSKeyStoreLoader.class);

    private KeyStore keystore;

    public KSKeyStoreLoader(String keystorePath, char[] password) {
        this(keystorePath, password, "JCEKS");
    }

    public KSKeyStoreLoader(String keystorePath, char[] password, String keystoreType) {
        log.debug("Forsøker å laste keystore av type \"{}\" fra \"{}\"", keystoreType, keystorePath);

        try {
            InputStream keystoreStream;
            if (new File(keystorePath).exists()) {
                log.debug("Fant keystore, laster inn fra fil");
                keystoreStream = new FileInputStream(keystorePath);
            } else {
                log.debug("Fant ikke keystore på filsystem, forsøker å laste som resource");
                keystoreStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(keystorePath);
            }

            if (keystoreStream == null) {
                throw new RuntimeException(String.format("Klarte ikke å laste keystore fra \"%s\"", keystorePath));
            }

            keystore = KeyStore.getInstance(keystoreType);
            keystore.load(keystoreStream, password);
            log.info("\"{}\" keystore \"{}\" lastet med {} aliases", keystoreType, keystorePath, keystore.size());
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        }

    }

    public KeyStore getKeystore() {
        return keystore;
    }

    public PrivateKey getPrivateKey(String alias, char[] password) {
        try {
            PrivateKey key = (PrivateKey) keystore.getKey(alias, password);
            if (key == null) {
                throw new RuntimeException(String.format("Fant ingen private key for alias \"%s\"", alias));
            }
            return key;
        } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public X509Certificate getPublicKey(String alias) {
        try {
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
            if (certificate == null) {
                throw new RuntimeException(String.format("Fant ingen public key for alias \"%s\"", alias));
            }
            return certificate;
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

}
