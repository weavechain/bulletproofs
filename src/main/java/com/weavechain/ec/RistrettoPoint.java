package com.weavechain.ec;

import com.weavechain.curve25519.RistrettoElement;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class RistrettoPoint implements ECPoint {

    public static final RistrettoPoint BASEPOINT = new RistrettoPoint(RistrettoElement.BASEPOINT);

    public static final RistrettoPoint IDENTITY = new RistrettoPoint(RistrettoElement.IDENTITY);

    private final RistrettoElement point;

    @Override
    public byte[] toByteArray() {
        return point.compress().toByteArray();
    }

    @Override
    public ECPoint compress() {
        return new CompressedRistrettoPoint(point.compress());
    }

    @Override
    public ECPoint decompress() {
        return this;
    }

    @Override
    public ECPoint add(ECPoint other) {
        return new RistrettoPoint(point.add(((RistrettoPoint)other).getPoint()));
    }

    @Override
    public ECPoint subtract(ECPoint other) {
        return new RistrettoPoint(point.subtract(((RistrettoPoint)other).getPoint()));
    }

    @Override
    public ECPoint multiply(Scalar scalar) {
        return new RistrettoPoint(point.multiply(((RScalar)scalar).getScalar()));
    }

    @Override
    public ECPoint negate() {
        return new RistrettoPoint(point.negate());
    }

    @Override
    public ECPoint dbl() {
        return new RistrettoPoint(point.dbl());
    }

    @Override
    public String toString() {
        return point.toString();
    }
}
