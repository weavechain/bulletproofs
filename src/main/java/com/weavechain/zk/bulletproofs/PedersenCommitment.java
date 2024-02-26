package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import com.weavechain.ec.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bitcoinj.base.Base58;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Getter
@AllArgsConstructor
public class PedersenCommitment {

    private final ECPoint b;

    private final ECPoint blinding;

    public static PedersenCommitment from(String encoding) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update(Base58.decode(encoding));
        byte[] digest = md.digest();

        return new PedersenCommitment(
                BulletProofs.getFactory().basepoint(),
                BulletProofs.getFactory().fromUniformBytes(digest)
        );
    }

    public static PedersenCommitment getDefault() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update(BulletProofs.getFactory().basepoint().compress().toByteArray());
        byte[] digest = md.digest();

        return new PedersenCommitment(
                BulletProofs.getFactory().basepoint(),
                BulletProofs.getFactory().fromUniformBytes(digest)
        );
    }

    public static PedersenCommitment getRandom() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        byte[] rndp = new byte[32];
        Utils.random().nextBytes(rndp);
        ECPoint committment = BulletProofs.getFactory().fromUniformBytes(rndp);
        md.update(committment.compress().toByteArray());
        byte[] digest = md.digest();

        return new PedersenCommitment(
                committment,
                BulletProofs.getFactory().fromUniformBytes(digest)
        );
    }

    public ECPoint commit(Scalar value, Scalar blinding) {
        return b.multiply(value).add(this.blinding.multiply(blinding)).compress();
    }
}
