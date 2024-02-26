package com.weavechain.ec;

public interface Scalar {

    byte[] toByteArray();

    Scalar invert();

    Scalar square();

    Scalar reduce();

    Scalar add(Scalar other);

    Scalar subtract(Scalar other);

    Scalar multiply(Scalar other);

    Scalar divide(Scalar other);

    Scalar multiplyAndAdd(Scalar mul, Scalar add);

    byte[] toRadix2w(int w);
}
