package com.weavechain.ec;

public interface ECPoint {

    byte[] toByteArray();

    ECPoint compress();

    ECPoint decompress();

    ECPoint add(ECPoint other);

    ECPoint subtract(ECPoint other);

    ECPoint multiply(Scalar scalar);

    ECPoint negate();

    ECPoint dbl();
}
