package no.ks.kryptering;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

@SuppressWarnings("WeakerAccess")
public class CMSKrypteringImpl implements CMSArrayKryptering, CMSStreamKryptering {

    private static final int DEFAULT_BUFFER_SIZE = 8192;
    private final Provider defaultProvider;
    private final ASN1ObjectIdentifier cmsEncryptionAlgorithm;
    private final AlgorithmIdentifier keyEncryptionScheme;

    /**
     * OBS! Relativt kostbar operasjon. Ikke opprett en ny instans av denne hver gang den skal brukes, da dette kan føre til minnelekkasje grunnet bug i JDK:
     * https://bugs.openjdk.java.net/browse/JDK-8168469
     */
    public CMSKrypteringImpl() {
        this.defaultProvider = new BouncyCastleProvider();
        Security.addProvider(this.defaultProvider);
        this.keyEncryptionScheme = this.rsaesOaepIdentifier();
        this.cmsEncryptionAlgorithm = CMSAlgorithm.AES256_CBC;
    }

    private AlgorithmIdentifier rsaesOaepIdentifier() {
        AlgorithmIdentifier hash = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier mask = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hash);
        AlgorithmIdentifier pSource = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0]));
        RSAESOAEPparams parameters = new RSAESOAEPparams(hash, mask, pSource);
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, parameters);
    }

    @Override
    public byte[] krypterData(byte[] bytes, X509Certificate sertifikat) {
        return krypterData(bytes, sertifikat, defaultProvider);
    }

    @Override
    public byte[] krypterData(byte[] bytes, X509Certificate sertifikat, Provider provider) {
        try {
            JceKeyTransRecipientInfoGenerator generator = getJceKeyTransRecipientInfoGenerator(sertifikat).setProvider(provider);
            CMSEnvelopedDataGenerator envelopedDataGenerator = new CMSEnvelopedDataGenerator();
            envelopedDataGenerator.addRecipientInfoGenerator(generator);
            OutputEncryptor contentEncryptor = getOutputEncryptor();
            CMSEnvelopedData cmsData = envelopedDataGenerator.generate(new CMSProcessableByteArray(bytes), contentEncryptor);
            return cmsData.getEncoded();
        } catch (CMSException e) {
            throw new RuntimeException("Kunne ikke generere Cryptographic Message Syntax for dokumentpakke", e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] dekrypterData(byte[] data, PrivateKey key) {
        return dekrypterData(data, key, defaultProvider);
    }

    @Override
    public byte[] dekrypterData(byte[] data, PrivateKey key, Provider provider) {
        try {
            JceKeyTransRecipient jceKeyTransRecipient = new JceKeyTransEnvelopedRecipient(key).setProvider(provider);
            CMSEnvelopedDataParser envDataParser = new CMSEnvelopedDataParser(data);
            RecipientInformationStore recipients = envDataParser.getRecipientInfos();
            RecipientInformation recipient = recipients.getRecipients().iterator().next();
            return recipient.getContent(jceKeyTransRecipient);
        } catch (CMSException e) {
            throw new KrypteringException("Dekryptering av forsendelsesdokumenter feilet", e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void krypterData(OutputStream kryptertOutputStream, InputStream inputStream, X509Certificate sertifikat) {
        krypterData(kryptertOutputStream, inputStream, sertifikat, defaultProvider);
    }

    @Override
    public void krypterData(OutputStream kryptertOutputStream, InputStream inputStream, X509Certificate sertifikat, Provider provider) {
        try (final ReadableByteChannel inputChannel = Channels.newChannel(inputStream);
             final WritableByteChannel outputChannel = Channels.newChannel(getKrypteringOutputStream(kryptertOutputStream, sertifikat, provider))) {

            final ByteBuffer buffer = ByteBuffer.allocateDirect(DEFAULT_BUFFER_SIZE);
            while (inputChannel.read(buffer) >= 0 || buffer.position() != 0) {
                ((Buffer) buffer).flip();
                outputChannel.write(buffer);
                buffer.compact();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OutputStream getKrypteringOutputStream(OutputStream kryptertOutputStream, X509Certificate sertifikat) {
        return getKrypteringOutputStream(kryptertOutputStream, sertifikat, defaultProvider);
    }

    @Override
    public OutputStream getKrypteringOutputStream(OutputStream kryptertOutputStream, X509Certificate sertifikat, Provider provider) {
        try {
            JceKeyTransRecipientInfoGenerator jceKeyTransRecipientInfoGenerator = getJceKeyTransRecipientInfoGenerator(sertifikat).setProvider(provider);
            CMSEnvelopedDataStreamGenerator envelopedDataGenerator = new CMSEnvelopedDataStreamGenerator();
            envelopedDataGenerator.addRecipientInfoGenerator(jceKeyTransRecipientInfoGenerator);
            OutputEncryptor contentEncryptor = getOutputEncryptor();
            return envelopedDataGenerator.open(kryptertOutputStream, contentEncryptor);
        } catch (CMSException e) {
            throw new RuntimeException("Kunne ikke generere Cryptographic Message Syntax for dokumentpakke", e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InputStream dekrypterData(InputStream encryptedStream, PrivateKey key) {
        return dekrypterData(encryptedStream, key, defaultProvider);
    }

    @Override
    public InputStream dekrypterData(InputStream encryptedStream, PrivateKey key, Provider provider) {
        try {
            CMSEnvelopedDataParser envDataParser = new CMSEnvelopedDataParser(new BufferedInputStream(encryptedStream, 1024 * 1024));
            RecipientInformationStore recipients = envDataParser.getRecipientInfos();
            RecipientInformation recipient = recipients.getRecipients().iterator().next();
            CMSTypedStream envelopedData = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(key).setProvider(provider));
            return envelopedData.getContentStream();
        } catch (CMSException e) {
            throw new KrypteringException("Dekryptering av forsendelsesdokumenter feilet", e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private OutputEncryptor getOutputEncryptor() throws CMSException {
        return (new JceCMSContentEncryptorBuilder(this.cmsEncryptionAlgorithm)).build();
    }

    private JceKeyTransRecipientInfoGenerator getJceKeyTransRecipientInfoGenerator(X509Certificate sertifikat) {
        try {
            return new JceKeyTransRecipientInfoGenerator(sertifikat, this.keyEncryptionScheme);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Feil med mottakers sertifikat", e);
        }
    }
}
