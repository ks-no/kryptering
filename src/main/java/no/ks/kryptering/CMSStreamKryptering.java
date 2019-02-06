package no.ks.kryptering;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public interface CMSStreamKryptering {
    void krypterData(OutputStream kryptertOutputStream, InputStream inputStream, X509Certificate sertifikat);
    void krypterData(OutputStream kryptertOutputStream, InputStream inputStream, X509Certificate sertifikat, Provider provider);
    InputStream dekrypterData(InputStream encryptedStream, PrivateKey key);
    InputStream dekrypterData(InputStream encryptedStream, PrivateKey key, Provider provider);
    OutputStream getKrypteringOutputStream(OutputStream kryptertOutputStream, X509Certificate sertifikat);
    OutputStream getKrypteringOutputStream(OutputStream kryptertOutputStream, X509Certificate sertifikat, Provider provider);
}
