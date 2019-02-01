package no.ks.kryptering;

public class KrypteringException extends RuntimeException {

    public KrypteringException() {

    }
    public KrypteringException(String message) {
        super(message);
    }

    public KrypteringException(String message, Throwable cause) {
        super(message, cause);
    }

    public KrypteringException(Throwable cause) {
        super(cause);
    }

    public KrypteringException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
