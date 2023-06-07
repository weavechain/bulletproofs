package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bitcoinj.core.Base58;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Getter
@AllArgsConstructor
public class PedersenCommitment {

    private final RistrettoElement b;

    private final RistrettoElement blinding;

    public static PedersenCommitment from(String encoding) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update(Base58.decode(encoding));
        byte[] digest = md.digest();

        return new PedersenCommitment(
                RistrettoElement.BASEPOINT,
                RistrettoElement.fromUniformBytes(digest)
        );
    }

    public static PedersenCommitment getDefault() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update(RistrettoElement.BASEPOINT.compress().toByteArray());
        byte[] digest = md.digest();

        return new PedersenCommitment(
                RistrettoElement.BASEPOINT,
                RistrettoElement.fromUniformBytes(digest)
        );
    }

    public static PedersenCommitment getRandom() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        byte[] rndp = new byte[32];
        Utils.random().nextBytes(rndp);
        RistrettoElement committment = RistrettoElement.fromUniformBytes(rndp);
        md.update(committment.compress().toByteArray());
        byte[] digest = md.digest();

        return new PedersenCommitment(
                committment,
                RistrettoElement.fromUniformBytes(digest)
        );
    }

    public CompressedRistretto commit(Scalar value, Scalar blinding) {
        return b.multiply(value).add(this.blinding.multiply(blinding)).compress();
    }
}
