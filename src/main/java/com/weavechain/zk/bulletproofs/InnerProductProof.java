package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import com.weavechain.ec.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Getter
@AllArgsConstructor
public class InnerProductProof {

    private final List<ECPoint> L;

    private final List<ECPoint> R;

    private final Scalar a;

    private final Scalar b;

    public void pack(MessageBufferPacker packer) throws IOException {
        packer.writePayload(a.toByteArray());
        packer.writePayload(b.toByteArray());

        packer.packInt(L.size());
        for (int i = 0; i < L.size(); i++) {
            packer.writePayload(L.get(i).toByteArray());
        }
        packer.packInt(R.size());
        for (int i = 0; i < R.size(); i++) {
            packer.writePayload(R.get(i).toByteArray());
        }
    }

    public static InnerProductProof unpack(MessageUnpacker unpacker) throws IOException {
        Scalar a = BulletProofs.getFactory().fromBits(unpacker.readPayload(32));
        Scalar b = BulletProofs.getFactory().fromBits(unpacker.readPayload(32));


        List<ECPoint> L = new ArrayList<>();
        int llen = unpacker.unpackInt();
        for (int i = 0; i < llen; i++) {
            L.add(BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32)));
        }

        List<ECPoint> R = new ArrayList<>();
        int rlen = unpacker.unpackInt();
        for (int i = 0; i < rlen; i++) {
            R.add(BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32)));
        }

        return new InnerProductProof(L, R, a, b);
    }

    public IPPVer scalarsVer(int n, Transcript transcript) {
        int logN = L.size();
        if (logN >= 32 || n != (1 << logN)) {
            return null;
        }

        transcript.append("dom-sep", "ipp");
        transcript.append("n", n);

        List<Scalar> challenges = new ArrayList<>();
        List<Scalar> invChallenges = new ArrayList<>();
        Scalar allInv = null;
        for (int i = 0; i < L.size(); i++) {
            if (!transcript.validateAndAppend("L", L.get(i))) {
                return null;
            }
            if (!transcript.validateAndAppend("R", R.get(i))) {
                return null;
            }

            Scalar c = transcript.challengeScalar("u");
            challenges.add(c);
            Scalar cinv = c.invert();
            invChallenges.add(cinv);
            allInv = allInv != null ? allInv.multiply(cinv) : cinv;
        }

        for (int i = 0; i < logN; i++) {
            challenges.set(i, challenges.get(i).multiply(challenges.get(i)));
            invChallenges.set(i, invChallenges.get(i).multiply(invChallenges.get(i)));
        }

        List<Scalar> s = new ArrayList<>();
        s.add(allInv != null ? allInv : BulletProofs.getFactory().one());
        for (int i = 1; i < n; i++) {
            int logI = (32 - 1 - Integer.numberOfLeadingZeros(i));
            int k = 1 << logI;
            s.add(s.get(i - k).multiply(challenges.get(logN - logI - 1)));
        }

        return new IPPVer(challenges, invChallenges, s);
    }

    public static InnerProductProof create(Transcript transcript, ECPoint Q, List<Scalar> G_fact, List<Scalar> H_fact, List<ECPoint> G, List<ECPoint> H, List<Scalar> a, List<Scalar> b) {
        int n = G.size();
        if (n != H.size() || n != a.size() || n != b.size() || n != G_fact.size() || n != H_fact.size()) {
            return null;
        }
        if (n != (n & Integer.highestOneBit(n))) { //length must be power of 2
            return null;
        }

        transcript.append("dom-sep", "ipp");
        transcript.append("n", n);

        List<ECPoint> L_vec = new ArrayList<>();
        List<ECPoint> R_vec = new ArrayList<>();

        if (n != 1) {
            n = n >> 1;

            List<Scalar> a_L = a.subList(0, n);
            List<Scalar> a_R = a.subList(n, a.size());
            List<Scalar> b_L = b.subList(0, n);
            List<Scalar> b_R = b.subList(n, b.size());
            List<ECPoint> G_L = G.subList(0, n);
            List<ECPoint> G_R = G.subList(n, G.size());
            List<ECPoint> H_L = H.subList(0, n);
            List<ECPoint> H_R = H.subList(n, H.size());

            Scalar c_L = Utils.innerProduct(a_L, b_R);
            Scalar c_R = Utils.innerProduct(a_R, b_L);

            List<Scalar> za_L = new ArrayList<>();
            List<Scalar> za_R = new ArrayList<>();
            List<Scalar> zb_L = new ArrayList<>();
            List<Scalar> zb_R = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                za_L.add(a_L.get(i).multiply(G_fact.get(n + i)));
                za_R.add(a_R.get(i).multiply(G_fact.get(i)));
                zb_L.add(b_L.get(i).multiply(H_fact.get(n + i)));
                zb_R.add(b_R.get(i).multiply(H_fact.get(i)));
            }

            ECPoint L = Utils.multiscalarMul(c_L, za_L, zb_R, Q, G_R, H_L).compress();
            ECPoint R = Utils.multiscalarMul(c_R, za_R, zb_L, Q, G_L, H_R).compress();

            L_vec.add(L);
            R_vec.add(R);

            transcript.append("L", L);
            transcript.append("R", R);

            Scalar u = transcript.challengeScalar("u");
            Scalar u_inv = u.invert();

            for (int i = 0; i < n; i++) {
                a_L.set(i, a_L.get(i).multiply(u).add(u_inv.multiply(a_R.get(i))));
                b_L.set(i, b_L.get(i).multiply(u_inv).add(u.multiply(b_R.get(i))));
                G_L.set(i, BulletProofs.getFactory().mulOptimized(u_inv.multiply(G_fact.get(i)), u.multiply(G_fact.get(n + i)), G_L.get(i), G_R.get(i)));
                H_L.set(i, BulletProofs.getFactory().mulOptimized(u.multiply(H_fact.get(i)), u_inv.multiply(H_fact.get(n + i)), H_L.get(i), H_R.get(i)));
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        while (n != 1) {
            n = n >> 1;

            List<Scalar> a_L = a.subList(0, n);
            List<Scalar> a_R = a.subList(n, a.size());
            List<Scalar> b_L = b.subList(0, n);
            List<Scalar> b_R = b.subList(n,b.size());
            List<ECPoint> G_L = G.subList(0, n);
            List<ECPoint> G_R = G.subList(n, G.size());
            List<ECPoint> H_L = H.subList(0, n);
            List<ECPoint> H_R = H.subList(n, H.size());

            Scalar c_L = Utils.innerProduct(a_L, b_R);
            Scalar c_R = Utils.innerProduct(a_R, b_L);

            ECPoint L = Utils.multiscalarMul(c_L, a_L, b_R, Q, G_R, H_L).compress();
            ECPoint R = Utils.multiscalarMul(c_R, a_R, b_L, Q, G_L, H_R).compress();

            L_vec.add(L);
            R_vec.add(R);

            transcript.append("L", L);
            transcript.append("R", R);

            Scalar u = transcript.challengeScalar("u");
            Scalar u_inv = u.invert();

            for (int i = 0; i < n; i++) {
                a_L.set(i, a_L.get(i).multiply(u).add(u_inv.multiply(a_R.get(i))));
                b_L.set(i, b_L.get(i).multiply(u_inv).add(u.multiply(b_R.get(i))));
                G_L.set(i, BulletProofs.getFactory().mulOptimized(u_inv, u, G_L.get(i), G_R.get(i)));
                H_L.set(i, BulletProofs.getFactory().mulOptimized(u, u_inv, H_L.get(i), H_R.get(i)));
            }

            a = a_L;
            b = b_L;
            G = G_L;
            H = H_L;
        }

        return new InnerProductProof(L_vec, R_vec, a.get(0), b.get(0));
    }

    @Getter
    @AllArgsConstructor
    public static class IPPVer {

        private final List<Scalar> u_sq;

        private final List<Scalar> u_inv_sq;

        private final List<Scalar> s;
    }
}
