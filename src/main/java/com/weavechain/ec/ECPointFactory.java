package com.weavechain.ec;

import com.weavechain.zk.bulletproofs.LinearCombination;

import java.util.List;

public interface ECPointFactory {

    ECPoint basepoint();

    ECPoint identity();

    Scalar zero();

    Scalar one();

    Scalar minus_one();

    LinearCombination one_lc();

    LinearCombination zero_lc();

    ECPoint fromCompressed(final byte[] data);

    ECPoint fromUniformBytes(byte[] data);

    Scalar fromBits(byte[] data);

    Scalar fromBytesModOrderWide(byte[] data);

    ECPoint mulOptimized(Scalar s1, Scalar s2, ECPoint p1, ECPoint p2);

    ECPoint multiscalarMulOpt(Scalar s1, List<Scalar> s2, List<Scalar> s3, ECPoint p1, List<ECPoint> p2, List<ECPoint> p3);
}
