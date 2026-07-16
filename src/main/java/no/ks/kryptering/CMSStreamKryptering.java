package no.ks.kryptering;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public interface CMSStreamKryptering {
    /**
     * Encrypts data from the provided input stream and writes the encrypted result to the output stream
     * using the default provider.
     *
     * @param kryptertOutputStream the output stream where encrypted data will be written
     * @param inputStream the input stream containing plaintext data to encrypt
     * @param sertifikat the X509 certificate used for encryption
     */
    void krypterData(OutputStream kryptertOutputStream, InputStream inputStream, X509Certificate sertifikat);

    /**
     * Encrypts data from the provided input stream and writes the encrypted result to the output stream
     * using a custom provider.
     *
     * @param kryptertOutputStream the output stream where encrypted data will be written
     * @param inputStream the input stream containing plaintext data to encrypt
     * @param sertifikat the X509 certificate used for encryption
     * @param provider the cryptographic provider to use for encryption
     */
    void krypterData(OutputStream kryptertOutputStream, InputStream inputStream, X509Certificate sertifikat, Provider provider);

    /**
     * Encrypts data written via the provided {@link PlaintextWriter} and writes the encrypted result
     * to the output stream using the default provider.
     *
     * @param kryptertOutputStream the output stream where encrypted data will be written
     * @param writer the plaintext writer that provides data to encrypt
     * @param sertifikat the X509 certificate used for encryption
     */
    void krypterData(OutputStream kryptertOutputStream, PlaintextWriter writer, X509Certificate sertifikat);

    /**
     * Encrypts data written via the provided {@link PlaintextWriter} and writes the encrypted result
     * to the output stream using a custom provider.
     *
     * @param kryptertOutputStream the output stream where encrypted data will be written
     * @param writer the plaintext writer that provides data to encrypt
     * @param sertifikat the X509 certificate used for encryption
     * @param provider the cryptographic provider to use for encryption
     */
    void krypterData(OutputStream kryptertOutputStream, PlaintextWriter writer, X509Certificate sertifikat, Provider provider);

    /**
     * Decrypts data from the provided encrypted input stream using the default provider.
     *
     * @param encryptedStream the input stream containing encrypted data
     * @param key the private key used for decryption
     * @return an input stream providing the decrypted data
     * @throws KrypteringException if decryption fails
     */
    InputStream dekrypterData(InputStream encryptedStream, PrivateKey key);

    /**
     * Decrypts data from the provided encrypted input stream using a custom provider.
     *
     * @param encryptedStream the input stream containing encrypted data
     * @param key the private key used for decryption
     * @param provider the cryptographic provider to use for decryption
     * @return an input stream providing the decrypted data
     * @throws KrypteringException if decryption fails
     */
    InputStream dekrypterData(InputStream encryptedStream, PrivateKey key, Provider provider);

    /**
     * Returns an output stream that encrypts data written to it using the default provider.
     *
     * @param kryptertOutputStream the underlying output stream where encrypted data will be written
     * @param sertifikat the X509 certificate used for encryption
     * @return an output stream that encrypts data as it is written
     */
    OutputStream getKrypteringOutputStream(OutputStream kryptertOutputStream, X509Certificate sertifikat);

    /**
     * Returns an output stream that encrypts data written to it using a custom provider.
     *
     * @param kryptertOutputStream the underlying output stream where encrypted data will be written
     * @param sertifikat the X509 certificate used for encryption
     * @param provider the cryptographic provider to use for encryption
     * @return an output stream that encrypts data as it is written
     */
    OutputStream getKrypteringOutputStream(OutputStream kryptertOutputStream, X509Certificate sertifikat, Provider provider);
}
