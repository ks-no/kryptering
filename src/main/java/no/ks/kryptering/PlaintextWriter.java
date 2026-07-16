package no.ks.kryptering;

import java.io.IOException;
import java.io.OutputStream;

@FunctionalInterface
public interface PlaintextWriter {
    void writeTo(OutputStream outputStream) throws IOException;
}
