package no.ks.kryptering;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

class CMSDataKrypteringTest {

    private static final String KEYSTORE_PATH = "keystore.p12";
    private static final String KEYSTORE_ALIAS = "kryptering";
    private static final String KEYSTORE_PASSWORD = "test1234";

    private static final KSKeyStoreLoader KEY_STORE_LOADER = new KSKeyStoreLoader(KEYSTORE_PATH, KEYSTORE_PASSWORD.toCharArray(), "PKCS12");
    private static final PrivateKey PRIVATE_KEY = KEY_STORE_LOADER.getPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD.toCharArray());
    private static final X509Certificate PUBLIC_KEY = KEY_STORE_LOADER.getPublicKey(KEYSTORE_ALIAS);

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    private static final Random r = new Random();

    @Test
    @DisplayName("Kryptering og dekryptering av byte array")
    void krypterDekrypterArray() {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        byte[] kryptertData = kryptering.krypterData(data, PUBLIC_KEY);
        byte[] dekryptertData = kryptering.dekrypterData(kryptertData, PRIVATE_KEY);

        assertFalse(Arrays.equals(data, kryptertData));
        assertArrayEquals(data, dekryptertData);
    }

    @Test
    @DisplayName("Kryptering og dekryptering av byte array med spesifisert provider")
    void krypterDekrypterArrayProvider() {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        byte[] kryptertData = kryptering.krypterData(data, PUBLIC_KEY, BC_PROVIDER);
        byte[] dekryptertData = kryptering.dekrypterData(kryptertData, PRIVATE_KEY, BC_PROVIDER);

        assertFalse(Arrays.equals(data, kryptertData));
        assertArrayEquals(data, dekryptertData);
    }

    @Test
    @DisplayName("Kryptering og dekryptering av stream")
    void krypterDekrypterStream() throws IOException, InterruptedException, TimeoutException, ExecutionException {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        PipedInputStream pis = new PipedInputStream();
        PipedOutputStream pos = new PipedOutputStream(pis);

        Future<?> future = Executors.newFixedThreadPool(1).submit(() -> {
            try {
                kryptering.krypterData(pos, new ByteArrayInputStream(data), PUBLIC_KEY);
                pos.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        byte[] kryptertData = IOUtils.toByteArray(pis);
        InputStream dekryptertData = kryptering.dekrypterData(new ByteArrayInputStream(kryptertData), PRIVATE_KEY);

        assertFalse(Arrays.equals(data, kryptertData));
        assertTrue(IOUtils.contentEquals(new ByteArrayInputStream(data), dekryptertData));
        future.get(1, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Kryptering og dekryptering av stream med spesifisert provider")
    void krypterDekrypterStreamProvider() throws IOException, InterruptedException, TimeoutException, ExecutionException {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        PipedInputStream pis = new PipedInputStream();
        PipedOutputStream pos = new PipedOutputStream(pis);

        Future<?> future = Executors.newFixedThreadPool(1).submit(() -> {
            try {
                kryptering.krypterData(pos, new ByteArrayInputStream(data), PUBLIC_KEY, BC_PROVIDER);
                pos.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        byte[] kryptertData = IOUtils.toByteArray(pis);
        InputStream dekryptertData = kryptering.dekrypterData(new ByteArrayInputStream(kryptertData), PRIVATE_KEY, BC_PROVIDER);

        assertFalse(Arrays.equals(data, kryptertData));
        assertTrue(IOUtils.contentEquals(new ByteArrayInputStream(data), dekryptertData));
        future.get(1, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Get kryptering stream, skriv data og dekrypter")
    void getKrypteringOutputStream() throws IOException, InterruptedException, TimeoutException, ExecutionException {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        PipedInputStream pis = new PipedInputStream();
        PipedOutputStream pos = new PipedOutputStream(pis);

        OutputStream krypteringOutputStream = kryptering.getKrypteringOutputStream(pos, PUBLIC_KEY);
        Future<?> future = Executors.newFixedThreadPool(1).submit(() -> {
            try {
                krypteringOutputStream.write(data);
                krypteringOutputStream.close();
                pos.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        byte[] kryptertData = IOUtils.toByteArray(pis);
        InputStream dekryptertData = kryptering.dekrypterData(new ByteArrayInputStream(kryptertData), PRIVATE_KEY);

        assertFalse(Arrays.equals(data, kryptertData));
        assertTrue(IOUtils.contentEquals(new ByteArrayInputStream(data), dekryptertData));
        future.get(1, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Get kryptering stream, skriv data og dekrypter med spesifisert provider")
    void getKrypteringOutputStreamProvider() throws IOException, InterruptedException, TimeoutException, ExecutionException {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        PipedInputStream pis = new PipedInputStream();
        PipedOutputStream pos = new PipedOutputStream(pis);

        OutputStream krypteringOutputStream = kryptering.getKrypteringOutputStream(pos, PUBLIC_KEY, BC_PROVIDER);
        Future<?> future = Executors.newFixedThreadPool(1).submit(() -> {
            try {
                krypteringOutputStream.write(data);
                krypteringOutputStream.close();
                pos.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        byte[] kryptertData = IOUtils.toByteArray(pis);
        InputStream dekryptertData = kryptering.dekrypterData(new ByteArrayInputStream(kryptertData), PRIVATE_KEY, BC_PROVIDER);

        assertFalse(Arrays.equals(data, kryptertData));
        assertTrue(IOUtils.contentEquals(new ByteArrayInputStream(data), dekryptertData));
        future.get(1, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Kryptering som stream og dekryptering som array")
    void krypterStreamDekrypterArray() throws IOException, InterruptedException, ExecutionException, TimeoutException {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        PipedInputStream pis = new PipedInputStream();
        PipedOutputStream pos = new PipedOutputStream(pis);

        Future<?> future = Executors.newFixedThreadPool(1).submit(() -> {
            try {
                kryptering.krypterData(pos, new ByteArrayInputStream(data), PUBLIC_KEY, BC_PROVIDER);
                pos.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        byte[] kryptertData = IOUtils.toByteArray(pis);
        byte[] dekryptertData = kryptering.dekrypterData(kryptertData, PRIVATE_KEY);

        assertFalse(Arrays.equals(data, kryptertData));
        assertArrayEquals(data, dekryptertData);
        future.get(1, TimeUnit.SECONDS);
    }

    @Test
    @DisplayName("Kryptering som array og dekryptering som stream")
    void krypterArrayDekrypterStream() throws IOException {
        CMSKrypteringImpl kryptering = new CMSKrypteringImpl();

        byte[] data = getRandomBytes();

        byte[] kryptertData = kryptering.krypterData(data, PUBLIC_KEY, BC_PROVIDER);
        InputStream dekryptertData = kryptering.dekrypterData(new ByteArrayInputStream(kryptertData), PRIVATE_KEY, BC_PROVIDER);

        assertFalse(Arrays.equals(data, kryptertData));
        assertTrue(IOUtils.contentEquals(new ByteArrayInputStream(data), dekryptertData));
    }

    private byte[] getRandomBytes() {
        byte[] data = new byte[r.nextInt(9000000) + 1000000];
        r.nextBytes(data);
        return data;
    }
}
