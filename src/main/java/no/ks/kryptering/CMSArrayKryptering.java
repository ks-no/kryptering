package no.ks.kryptering;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public interface CMSArrayKryptering {
    byte[] krypterData(byte[] bytes, X509Certificate sertifikat);
    byte[] krypterData(byte[] bytes, X509Certificate sertifikat, Provider provider);
    byte[] dekrypterData(byte[] data, PrivateKey key);
    byte[] dekrypterData(byte[] data, PrivateKey key, Provider provider);
}
