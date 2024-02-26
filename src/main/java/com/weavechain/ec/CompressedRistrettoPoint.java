package com.weavechain.ec;

import com.weavechain.curve25519.*;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class CompressedRistrettoPoint implements ECPoint {

    static final Logger logger = LoggerFactory.getLogger(CompressedRistretto.class);

    private final CompressedRistretto point;

    public CompressedRistrettoPoint(byte[] data) {
        this(new CompressedRistretto(data));
    }

    @Override
    public byte[] toByteArray() {
        return point.toByteArray();
    }

    @Override
    public ECPoint compress() {
        return this;
    }

    @Override
    public ECPoint decompress() {
        try {
            return new RistrettoPoint(point.decompress());
        } catch (InvalidEncodingException e) {
            logger.error("Failed decompression", e);
            return null;
        }
    }

    @Override
    public ECPoint add(ECPoint other) {
        return null;
    }

    @Override
    public ECPoint subtract(ECPoint other) {
        return null;
    }

    @Override
    public ECPoint multiply(Scalar scalar) {
        return null;
    }

    @Override
    public ECPoint negate() {
        return null;
    }

    @Override
    public ECPoint dbl() {
        return null;
    }

    @Override
    public String toString() {
        return point.toString();
    }
}
