package com.weavechain.ec;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class RScalar implements Scalar {

    public static final Scalar ZERO = new RScalar(com.weavechain.curve25519.Scalar.ZERO);

    public static final Scalar ONE = new RScalar(com.weavechain.curve25519.Scalar.ONE);

    public static final Scalar MINUS_ONE = ZERO.subtract(ONE);

    private final com.weavechain.curve25519.Scalar scalar;

    @Override
    public byte[] toByteArray() {
        return scalar.toByteArray();
    }

    @Override
    public Scalar invert() {
        return new RScalar(scalar.invert());
    }

    @Override
    public Scalar square() {
        return new RScalar(scalar.square());
    }

    @Override
    public Scalar reduce() {
        return new RScalar(scalar.reduce());
    }

    @Override
    public Scalar add(Scalar other) {
        return new RScalar(scalar.add(((RScalar)other).scalar));
    }

    @Override
    public Scalar subtract(Scalar other) {
        return new RScalar(scalar.subtract(((RScalar)other).scalar));
    }

    @Override
    public Scalar multiply(Scalar other) {
        return new RScalar(scalar.multiply(((RScalar)other).scalar));
    }

    @Override
    public Scalar divide(Scalar other) {
        return new RScalar(scalar.divide(((RScalar)other).scalar));
    }

    @Override
    public Scalar multiplyAndAdd(Scalar mul, Scalar add) {
        return new RScalar(scalar.multiplyAndAdd(((RScalar)mul).scalar, ((RScalar)add).scalar));
    }

    @Override
    public byte[] toRadix2w(int w) {
        return scalar.toRadix2w(w);
    }

    @Override
    public String toString() {
        return scalar.toString();
    }
}
