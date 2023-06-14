package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.CompressedRistretto;
import com.weavechain.curve25519.RistrettoElement;
import com.weavechain.curve25519.Scalar;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

@AllArgsConstructor
public class Prover extends ConstraintSystem {

    static final Logger logger = LoggerFactory.getLogger(Prover.class);

    private final Transcript transcript;

    private final PedersenCommitment pedersenCommitment;

    private final List<LinearCombination> constraints = new ArrayList<>();

    private final List<Scalar> leftGates = new ArrayList<>();

    private final List<Scalar> rightGates = new ArrayList<>();

    private final List<Scalar> outputGates = new ArrayList<>();

    private final List<Scalar> values = new ArrayList<>();

    private final List<Scalar> blindings = new ArrayList<>();

    private final List<Consumer<Prover>> deferredConstraints = new ArrayList<>();

    private Integer pendingMultiplier = null;

    public Prover(Transcript transcript, PedersenCommitment pedersenCommitment) {
        this.transcript = transcript;
        this.pedersenCommitment = pedersenCommitment;
    }

    public Commitment commit(Scalar value, Scalar blinding) {
        int size = values.size();

        values.add(value);
        blindings.add(blinding);

        CompressedRistretto commitment = pedersenCommitment.commit(value, blinding);
        transcript.append("V", commitment);

        return new Commitment(commitment, new Variable(VariableType.committed, size));
    }

    @Override
    public void constrain(LinearCombination lc) {
        constraints.add(lc);
    }

    @Override
    public LRO allocateMultiplier(Scalar left, Scalar right) {
        if (left != null && right != null) {
            Variable l = Variable.multiplierLeft(leftGates.size());
            Variable r = Variable.multiplierRight(rightGates.size());
            Variable o = Variable.multiplierOutput(outputGates.size());

            leftGates.add(left);
            rightGates.add(right);
            outputGates.add(left.multiply(right));

            return new LRO(l, r, o);
        } else {
            return null;
        }
    }

    private void randomizedConstraints() {
        pendingMultiplier = null;

        if (deferredConstraints.isEmpty()) {
            transcript.phase1();
        } else {
            transcript.phase2();

            for (Consumer<Prover> fn : deferredConstraints) {
                fn.accept(this);
            }
        }
    }

    public VecPoly flattenedConstraints(Scalar z) {
        int n = leftGates.size();
        int m = values.size();

        List<Scalar> wL = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));
        List<Scalar> wR = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));
        List<Scalar> wO = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));
        List<Scalar> wV = new ArrayList<>(Collections.nCopies(m, Scalar.ZERO));

        Scalar expz = z;
        for (LinearCombination lc : constraints) {
            for (Term t : lc.getTerms()) {
                if (VariableType.multiplier_left.equals(t.getVariable().getType())) {
                    wL.set(t.getVariable().getIndex(), wL.get(t.getVariable().getIndex()).add(expz.multiply(t.getScalar())));
                } else if (VariableType.multiplier_right.equals(t.getVariable().getType())) {
                    wR.set(t.getVariable().getIndex(), wR.get(t.getVariable().getIndex()).add(expz.multiply(t.getScalar())));
                } else if (VariableType.multiplier_output.equals(t.getVariable().getType())) {
                    wO.set(t.getVariable().getIndex(), wO.get(t.getVariable().getIndex()).add(expz.multiply(t.getScalar())));
                } else if (VariableType.committed.equals(t.getVariable().getType())) {
                    wV.set(t.getVariable().getIndex(), wV.get(t.getVariable().getIndex()).subtract(expz.multiply(t.getScalar())));
                }
            }

            expz = expz.multiply(z);
        }

        VecPoly result = new VecPoly(null);
        result.add(wL);
        result.add(wR);
        result.add(wO);
        result.add(wV);
        return result;
    }

    public R1CSProof prove(BulletProofGenerators generators) {
        transcript.append("m", values.size());

        //TODO: rekey with blindings and use a different RNG, see https://merlin.cool/transcript/rng.html

        int n1 = leftGates.size();

        if (generators.getCapacity() < n1) {
            throw new IllegalStateException("Invalid generators length " + generators.getCapacity() + " < " + n1);
        }

        BulletProofGenShare gen = generators.getShare(0);

        Scalar i_blinding1 = Utils.randomScalar();
        Scalar o_blinding1 = Utils.randomScalar();
        Scalar s_blinding1 = Utils.randomScalar();

        List<Scalar> s_L1 = new ArrayList<>();
        List<Scalar> s_R1 = new ArrayList<>();

        for (int i = 0; i < n1; i++) {
            s_L1.add(Utils.randomScalar());
            s_R1.add(Utils.randomScalar());
        }

        // A_I = <a_L, G> + <a_R, H> + i_blinding * B_blinding
        CompressedRistretto A_I1 = Utils.multiscalarMul(i_blinding1, leftGates, rightGates, pedersenCommitment.getBlinding(), gen.getG(n1), gen.getH(n1)).compress();
        transcript.append("A_I1", A_I1);

        // A_O = <a_O, G> + o_blinding * B_blinding
        CompressedRistretto A_O1 = Utils.multiscalarMul(o_blinding1, outputGates, pedersenCommitment.getBlinding(), gen.getG(n1)).compress();
        transcript.append("A_O1", A_O1);

        // S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
        CompressedRistretto S1 = Utils.multiscalarMul(s_blinding1, s_L1, s_R1, pedersenCommitment.getBlinding(), gen.getG(n1), gen.getH(n1)).compress();
        transcript.append("S1", S1);

        // Process the remaining constraints.
        randomizedConstraints();

        // Pad zeros to the next power of two (or do that implicitly when creating vectors)
        int n = leftGates.size();
        int n2 = n - n1;
        int nPadded = Utils.nextPowerOf2(n);
        int pad = nPadded - n;

        if (generators.getCapacity() < nPadded) {
            throw new IllegalStateException("Invalid generators length");
        }

        boolean has2ndPhase = n2 > 0;
        Scalar i_blinding2 = has2ndPhase ? Utils.randomScalar() : Scalar.ZERO;
        Scalar o_blinding2 = has2ndPhase ? Utils.randomScalar() : Scalar.ZERO;
        Scalar s_blinding2 = has2ndPhase ? Utils.randomScalar() : Scalar.ZERO;

        List<Scalar> s_L2 = new ArrayList<>();
        List<Scalar> s_R2 = new ArrayList<>();
        for (int i = 0; i < n2; i++) {
            s_L2.add(Utils.randomScalar());
            s_R2.add(Utils.randomScalar());
        }

        // A_I = <a_L, G> + <a_R, H> + i_blinding * B_blinding
        CompressedRistretto A_I2 = has2ndPhase
                ? Utils.multiscalarMul(i_blinding2, leftGates.subList(n1, leftGates.size()), rightGates.subList(n1, rightGates.size()), pedersenCommitment.getBlinding(), gen.getG(n).subList(n1, gen.getG(n).size()), gen.getH(n).subList(n1, gen.getH(n).size())).compress()
                : RistrettoElement.IDENTITY.compress();
        transcript.append("A_I2", A_I2);

        // A_O = <a_O, G> + o_blinding * B_blinding
        CompressedRistretto A_O2 = has2ndPhase
                ? Utils.multiscalarMul(o_blinding2, outputGates.subList(n1, outputGates.size()), pedersenCommitment.getBlinding(), gen.getG(n).subList(n1, gen.getG(n).size())).compress()
                : RistrettoElement.IDENTITY.compress();
        transcript.append("A_O2", A_O2);

        // S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
        CompressedRistretto S2 = Utils.multiscalarMul(s_blinding2, s_L2, s_R2, pedersenCommitment.getBlinding(), gen.getG(n).subList(n1, gen.getG(n).size()), gen.getH(n).subList(n1, gen.getH(n).size())).compress();
        transcript.append("S2", S2);

        Scalar y = transcript.challengeScalar("y");
        Scalar z = transcript.challengeScalar("z");

        VecPoly wp = flattenedConstraints(z);
        List<Scalar> wL = wp.get(0);
        List<Scalar> wR = wp.get(1);
        List<Scalar> wO = wp.get(2);
        List<Scalar> wV = wp.get(3);

        VecPoly l_poly = new VecPoly(3, n);
        VecPoly r_poly = new VecPoly(3, n);

        Scalar exp_y = Scalar.ONE;
        Scalar y_inv = y.invert();

        List<Scalar> exp_y_inv = new ArrayList<>();
        Scalar eyinv = Scalar.ONE;
        for (int i = 0; i < nPadded; i++) {
            exp_y_inv.add(eyinv);
            eyinv = eyinv.multiply(y_inv);
        }

        int idx = 0;
        for (int i = 0; i < s_L1.size(); i++) {
            Scalar sl = s_L1.get(i);
            Scalar sr = s_R1.get(i);

            setPolyTerm(l_poly, r_poly, idx, wL, wR, wO, exp_y, exp_y_inv, sl, sr);

            exp_y = exp_y.multiply(y);
            idx++;
        }
        for (int i = 0; i < s_L2.size(); i++) {
            Scalar sl = s_L2.get(i);
            Scalar sr = s_R2.get(i);

            setPolyTerm(l_poly, r_poly, idx, wL, wR, wO, exp_y, exp_y_inv, sl, sr);

            exp_y = exp_y.multiply(y);
            idx++;
        }

        Poly t_poly = l_poly.spInnerProduct(r_poly);

        Scalar t_1_blinding = Utils.randomScalar();
        Scalar t_3_blinding = Utils.randomScalar();
        Scalar t_4_blinding = Utils.randomScalar();
        Scalar t_5_blinding = Utils.randomScalar();
        Scalar t_6_blinding = Utils.randomScalar();

        CompressedRistretto T_1 = pedersenCommitment.commit(t_poly.get(1), t_1_blinding);
        CompressedRistretto T_3 = pedersenCommitment.commit(t_poly.get(3), t_3_blinding);
        CompressedRistretto T_4 = pedersenCommitment.commit(t_poly.get(4), t_4_blinding);
        CompressedRistretto T_5 = pedersenCommitment.commit(t_poly.get(5), t_5_blinding);
        CompressedRistretto T_6 = pedersenCommitment.commit(t_poly.get(6), t_6_blinding);

        transcript.append("T_1", T_1);
        transcript.append("T_3", T_3);
        transcript.append("T_4", T_4);
        transcript.append("T_5", T_5);
        transcript.append("T_6", T_6);

        Scalar u = transcript.challengeScalar("u");
        Scalar x = transcript.challengeScalar("x");

        // t_2_blinding = <z*z^Q, W_V * v_blinding>
        Scalar t_2_blinding = Scalar.ZERO;
        for (int i = 0; i < blindings.size(); i++) {
            t_2_blinding = t_2_blinding.add(wV.get(i).multiply(blindings.get(i)));
        }

        Poly t_blinding_poly = new Poly(Scalar.ZERO, t_1_blinding, t_2_blinding, t_3_blinding, t_4_blinding, t_5_blinding, t_6_blinding);

        Scalar t_x = t_poly.at(x);
        Scalar t_x_blinding = t_blinding_poly.at(x);
        List<Scalar> l_vec = l_poly.at(x);
        for (int i = 0; i < pad; i++) {
            l_vec.add(Scalar.ZERO);
        }

        List<Scalar> r_vec = r_poly.at(x);
        for (int i = 0; i < pad; i++) {
            r_vec.add(Scalar.ZERO);
        }

        for (int i = n; i < nPadded; i++) {
            r_vec.set(i, Scalar.ZERO.subtract(exp_y));
            exp_y = exp_y.multiply(y);
        }

        Scalar i_blinding = i_blinding1.add(u.multiply(i_blinding2));
        Scalar o_blinding = o_blinding1.add(u.multiply(o_blinding2));
        Scalar s_blinding = s_blinding1.add(u.multiply(s_blinding2));

        Scalar e_blinding = x.multiply(i_blinding.add(x.multiply(o_blinding.add(x.multiply(s_blinding)))));

        transcript.append("t_x", t_x);
        transcript.append("t_x_blinding", t_x_blinding);
        transcript.append("e_blinding", e_blinding);

        Scalar w = transcript.challengeScalar("w");
        RistrettoElement Q = pedersenCommitment.getB().multiply(w);

        List<Scalar> G_factors = new ArrayList<>();
        List<Scalar> H_factors = new ArrayList<>();
        for (int i = 0; i < n1; i++) {
            G_factors.add(Scalar.ONE);
        }
        for (int i = 0; i < n2 + pad; i++) {
            G_factors.add(u);
        }
        for (int i = 0; i < exp_y_inv.size(); i++) {
            H_factors.add(exp_y_inv.get(i).multiply(G_factors.get(i)));
        }

        InnerProductProof ipp_proof = InnerProductProof.create(transcript, Q, G_factors, H_factors, gen.getG(nPadded), gen.getH(nPadded), l_vec, r_vec);

        return new R1CSProof(A_I1,
                A_O1,
                S1,
                A_I2,
                A_O2,
                S2,
                T_1,
                T_3,
                T_4,
                T_5,
                T_6,
                t_x,
                t_x_blinding,
                e_blinding,
                ipp_proof);
    }

    private void setPolyTerm(VecPoly l_poly, VecPoly r_poly, int idx, List<Scalar> wL, List<Scalar> wR, List<Scalar> wO, Scalar exp_y, List<Scalar> exp_y_inv, Scalar sl, Scalar sr) {
        l_poly.get(1).set(idx, leftGates.get(idx).add(exp_y_inv.get(idx).multiply(wR.get(idx))));
        l_poly.get(2).set(idx, outputGates.get(idx));
        l_poly.get(3).set(idx, sl);
        r_poly.get(0).set(idx, wO.get(idx).subtract(exp_y));
        r_poly.get(1).set(idx, exp_y.multiply(rightGates.get(idx)).add(wL.get(idx)));
        r_poly.get(3).set(idx, exp_y.multiply(sr));
    }

    public Scalar eval(LinearCombination lc) {
        Scalar result = Scalar.ZERO;
        for (Term t : lc.getTerms()) {
            if (VariableType.multiplier_left.equals(t.getVariable().getType())) {
                result = result.add(t.getScalar().multiply(leftGates.get(t.getVariable().getIndex())));
            } else if (VariableType.multiplier_right.equals(t.getVariable().getType())) {
                result = result.add(t.getScalar().multiply(rightGates.get(t.getVariable().getIndex())));
            } else if (VariableType.multiplier_output.equals(t.getVariable().getType())) {
                result = result.add(t.getScalar().multiply(outputGates.get(t.getVariable().getIndex())));
            } else if (VariableType.committed.equals(t.getVariable().getType())) {
                result = result.add(t.getScalar().multiply(values.get(t.getVariable().getIndex())));
            } else if (VariableType.one.equals(t.getVariable().getType())) {
                result = result.add(t.getScalar());
            }
        }

        return result;
    }

    @Override
    public LRO multiply(LinearCombination left, LinearCombination right) {
        Scalar sl = eval(left);
        Scalar sr = eval(right);
        Scalar so = sl.multiply(sr);

        Variable vl = Variable.multiplierLeft(leftGates.size());
        Variable vr = Variable.multiplierRight(rightGates.size());
        Variable vo = Variable.multiplierOutput(outputGates.size());

        leftGates.add(sl);
        rightGates.add(sr);
        outputGates.add(so);

        left.append(new Term(vl, Utils.MINUS_ONE));
        right.append(new Term(vr, Utils.MINUS_ONE));

        constrain(left);
        constrain(right);

        return new LRO(vl, vr, vo);
    }
}
