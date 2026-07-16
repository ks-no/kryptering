package no.ks.kryptering;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public interface CMSArrayKryptering {
    /**
     * Encrypts the provided byte array with the default provider.
     *
     * @param bytes the data to encrypt
     * @param sertifikat the X509 certificate used for encryption
     * @return the encrypted data as a byte array
     */
    byte[] krypterData(byte[] bytes, X509Certificate sertifikat);

    /**
     * Encrypts the provided byte array with a custom provider.
     *
     * @param bytes the data to encrypt
     * @param sertifikat the X509 certificate used for encryption
     * @param provider the cryptographic provider to use for encryption
     * @return the encrypted data as a byte array
     */
    byte[] krypterData(byte[] bytes, X509Certificate sertifikat, Provider provider);

    /**
     * Decrypts the provided byte array using the default provider.
     *
     * @param data the encrypted data to decrypt
     * @param key the private key used for decryption
     * @return the decrypted data as a byte array
     * @throws KrypteringException if decryption fails
     */
    byte[] dekrypterData(byte[] data, PrivateKey key);

    /**
     * Decrypts the provided byte array using a custom provider.
     *
     * @param data the encrypted data to decrypt
     * @param key the private key used for decryption
     * @param provider the cryptographic provider to use for decryption
     * @return the decrypted data as a byte array
     * @throws KrypteringException if decryption fails
     */
    byte[] dekrypterData(byte[] data, PrivateKey key, Provider provider);
}
