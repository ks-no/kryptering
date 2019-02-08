package no.ks.kryptering;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KSKeyStoreLoaderTest {

    private static final String PKCS12_KEYSTORE_PATH = "keystore.p12";
    private static final String PKCS12_KEYSTORE_PASSWORD = "test1234";
    private static final String JCEKS_KEYSTORE_PATH = "keystore.jks";
    private static final String JCEKS_KEYSTORE_PASSWORD = "test1234";

    @Test
    @DisplayName("Det skal være mulig å laste en PKCS12 keystore som en fil")
    void testLoadPKCS12Keystore() {
        new KSKeyStoreLoader(getClass().getClassLoader().getResource(JCEKS_KEYSTORE_PATH).getFile(), JCEKS_KEYSTORE_PASSWORD.toCharArray());
    }

    @Test
    @DisplayName("Det skal være mulig å laste en JCEKS keystore som en fil uten å spesifisere type")
    void testLoadKeystore() {
        new KSKeyStoreLoader(getClass().getClassLoader().getResource(PKCS12_KEYSTORE_PATH).getFile(), PKCS12_KEYSTORE_PASSWORD.toCharArray(), "PKCS12");
    }

    @Test
    @DisplayName("Det skal være mulig å laste en JCEKS keystore som en resource uten å spesifisere type")
    void testLoadKeystoreFraRessurs() {
        new KSKeyStoreLoader(JCEKS_KEYSTORE_PATH, JCEKS_KEYSTORE_PASSWORD.toCharArray());
    }

    @Test
    @DisplayName("Det skal være mulig å laste en PKCS12 keystore som en resource")
    void testLoadPKCS12KeystoreFraRessurs() {
        new KSKeyStoreLoader(PKCS12_KEYSTORE_PATH, PKCS12_KEYSTORE_PASSWORD.toCharArray(), "PKCS12");
    }

    @Test
    @DisplayName("Dersom feil passord er oppgitt ved lasting av keystore skal en exception kastes")
    void testLoadKeystoreFeilPassord() {
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                new KSKeyStoreLoader(getClass().getClassLoader().getResource(JCEKS_KEYSTORE_PATH).getFile(), UUID.randomUUID().toString().toCharArray()));

        assertThat(exception.getMessage(), containsString("Keystore was tampered with, or password was incorrect"));
    }

    @Test
    @DisplayName("Dersom feil type er oppgitt ved lasting av keystore skal en exception kastes")
    void testLoadKeystoreFeilType() {
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                new KSKeyStoreLoader(getClass().getClassLoader().getResource(JCEKS_KEYSTORE_PATH).getFile(), JCEKS_KEYSTORE_PASSWORD.toCharArray(), "PKCS12"));

        assertThat(exception.getMessage(), containsString("DerInputStream.getLength(): lengthTag=109, too big"));
    }

    @Test
    @DisplayName("Dersom keystore ikke finnes som fil eller resource skal en exception kastes")
    void testLoadIkkeEksisterendeKeystore() {
        String path = UUID.randomUUID().toString();
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                new KSKeyStoreLoader(path, UUID.randomUUID().toString().toCharArray()));

        assertThat(exception.getMessage(), is(String.format("Klarte ikke å laste keystore fra \"%s\"", path)));
    }

    @Test
    @DisplayName("Det skal være mulig å hente ut public key med alias fra en keystore")
    void testGetPublicKey() {
        KSKeyStoreLoader keyStoreLoader = new KSKeyStoreLoader(JCEKS_KEYSTORE_PATH, JCEKS_KEYSTORE_PASSWORD.toCharArray());

        X509Certificate publicKey = keyStoreLoader.getPublicKey("kryptering");
        assertThat(publicKey, notNullValue());
    }

    @Test
    @DisplayName("Dersom man forsøker å hente ut en public key for et alias som ikke finnes skal en exception kastes")
    void testGetPublicKeyIkkeEksisterende() {
        KSKeyStoreLoader keyStoreLoader = new KSKeyStoreLoader(JCEKS_KEYSTORE_PATH, JCEKS_KEYSTORE_PASSWORD.toCharArray());

        RuntimeException exception = assertThrows(RuntimeException.class, () -> keyStoreLoader.getPublicKey("ukjent"));
        assertThat(exception.getMessage(), is("Fant ingen public key for alias \"ukjent\""));
    }

    @Test
    @DisplayName("Det skal være mulig å hente ut private key med alias fra en keystore")
    void testGetPrivateKey() {
        KSKeyStoreLoader keyStoreLoader = new KSKeyStoreLoader(JCEKS_KEYSTORE_PATH, JCEKS_KEYSTORE_PASSWORD.toCharArray());

        PrivateKey privateKey = keyStoreLoader.getPrivateKey("kryptering", JCEKS_KEYSTORE_PASSWORD.toCharArray());
        assertThat(privateKey, notNullValue());
    }

    @Test
    @DisplayName("Dersom man forsøker å hente ut en private key for et alias som ikke finnes skal en exception kastes")
    void testGetPrivateKeyIkkeEksisterende() {
        KSKeyStoreLoader keyStoreLoader = new KSKeyStoreLoader(JCEKS_KEYSTORE_PATH, JCEKS_KEYSTORE_PASSWORD.toCharArray());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                keyStoreLoader.getPrivateKey("ukjent", UUID.randomUUID().toString().toCharArray()));
        assertThat(exception.getMessage(), is("Fant ingen private key for alias \"ukjent\""));
    }

    @Test
    @DisplayName("Dersom man forsøker å hente ut en eksisterende private key med feil passord skal en exception kastes")
    void testGetPrivateKeyFeilPassord() {
        KSKeyStoreLoader keyStoreLoader = new KSKeyStoreLoader(JCEKS_KEYSTORE_PATH, JCEKS_KEYSTORE_PASSWORD.toCharArray());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                keyStoreLoader.getPrivateKey("kryptering", UUID.randomUUID().toString().toCharArray()));
        assertThat(exception.getMessage(), containsString("Cannot recover key"));
    }
}
