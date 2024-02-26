package com.weavechain.ec;

import com.weavechain.curve25519.MulUtils;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.zk.bulletproofs.LinearCombination;

import java.util.ArrayList;
import java.util.List;

public class Curve25519Factory implements ECPointFactory {

    public static final LinearCombination LC_ONE = LinearCombination.from(RScalar.ONE);

    public static final LinearCombination LC_ZERO = LinearCombination.from(RScalar.ZERO);

    @Override
    public ECPoint basepoint() {
        return RistrettoPoint.BASEPOINT;
    }

    @Override
    public ECPoint identity() {
        return RistrettoPoint.IDENTITY;
    }

    @Override
    public Scalar zero() {
        return RScalar.ZERO;
    }

    @Override
    public Scalar one() {
        return RScalar.ONE;
    }

    @Override
    public Scalar minus_one() {
        return RScalar.MINUS_ONE;
    }

    @Override
    public LinearCombination one_lc() {
        return LC_ONE;
    }

    @Override
    public LinearCombination zero_lc() {
        return LC_ZERO;
    }

    @Override
    public ECPoint fromCompressed(final byte[] data) {
        return new CompressedRistrettoPoint(data);
    }

    @Override
    public ECPoint fromUniformBytes(final byte[] data) {
        return new RistrettoPoint(RistrettoElement.fromUniformBytes(data));
    }

    @Override
    public Scalar fromBits(byte[] data) {
        return new RScalar(com.weavechain.curve25519.Scalar.fromBits(data));
    }

    @Override
    public Scalar fromBytesModOrderWide(byte[] data) {
        return new RScalar(com.weavechain.curve25519.Scalar.fromBytesModOrderWide(data));
    }

    @Override
    public ECPoint mulOptimized(Scalar s1, Scalar s2, ECPoint p1, ECPoint p2) {
        return new RistrettoPoint(MulUtils.mulStraus(
                ((RScalar)s1).getScalar(),
                ((RScalar)s2).getScalar(),
                ((RistrettoPoint)p1).getPoint(),
                ((RistrettoPoint)p2).getPoint()
        ));
    }

    @Override
    public ECPoint multiscalarMulOpt(Scalar s1, List<Scalar> s2, List<Scalar> s3, ECPoint p1, List<ECPoint> p2, List<ECPoint> p3) {
        List<com.weavechain.curve25519.Scalar> cs2 = s2 != null ? new ArrayList<>() : null;
        if (s2 != null) {
            for (Scalar s : s2) {
                cs2.add(((RScalar)s).getScalar());
            }
        }
        List<com.weavechain.curve25519.Scalar> cs3 = s3 != null ? new ArrayList<>() : null;
        if (s3 != null) {
            for (Scalar s : s3) {
                cs3.add(((RScalar)s).getScalar());
            }
        }

        List<RistrettoElement> cp2 = p2 != null ? new ArrayList<>() : null;
        if (cp2 != null) {
            for (ECPoint s : p2) {
                cp2.add(((RistrettoPoint)s).getPoint());
            }
        }
        List<RistrettoElement> cp3 = p3 != null ? new ArrayList<>() : null;
        if (cp3 != null) {
            for (ECPoint s : p3) {
                cp3.add(((RistrettoPoint)s).getPoint());
            }
        }

        return new RistrettoPoint(MulUtils.multiscalarMulOpt(
                ((RScalar)s1).getScalar(),
                cs2,
                cs3,
                ((RistrettoPoint)p1).getPoint(),
                cp2,
                cp3
        ));
    }
}
