package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

public class Verifier extends ConstraintSystem {

    static final Logger logger = LoggerFactory.getLogger(Verifier.class);

    private final Transcript transcript;

    private final List<LinearCombination> constraints = new ArrayList<>();

    private final List<Consumer<Verifier>> deferredConstraints = new ArrayList<>();

    private final List<CompressedRistretto> values = new ArrayList<>();

    private int numVars = 0;

    private Integer pendingMultiplier = null;

    public Verifier(Transcript transcript) {
        this.transcript = transcript;
    }

    public Variable commit(CompressedRistretto commitment) {
        int size = values.size();

        values.add(commitment);
        transcript.append("V", commitment);

        return new Variable(VariableType.committed, size);
    }

    @Override
    public void constrain(LinearCombination lc) {
        constraints.add(lc);
    }

    @Override
    public LRO allocateMultiplier(Scalar left, Scalar right) {
        Variable l = Variable.multiplierLeft(numVars);
        Variable r = Variable.multiplierRight(numVars);
        Variable o = Variable.multiplierOutput(numVars);

        numVars++;

        return new LRO(l, r, o);
    }

    private void randomizedConstraints() {
        pendingMultiplier = null;

        if (deferredConstraints.isEmpty()) {
            transcript.phase1();
        } else {
            transcript.phase2();

            for (Consumer<Verifier> fn : deferredConstraints) {
                fn.accept(this);
            }
        }
    }

    public VecPoly flattenedConstraints(Scalar z) {
        int n = numVars;
        int m = values.size();

        List<Scalar> wL = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));
        List<Scalar> wR = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));
        List<Scalar> wO = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));
        List<Scalar> wV = new ArrayList<>(Collections.nCopies(m, Scalar.ZERO));
        Scalar wc = Scalar.ZERO;

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
                } else if (VariableType.one.equals(t.getVariable().getType())) {
                    wc = wc.subtract(expz.multiply(t.getScalar()));
                }
            }

            expz = expz.multiply(z);
        }

        VecPoly result = new VecPoly(wc);
        result.add(wL);
        result.add(wR);
        result.add(wO);
        result.add(wV);
        return result;
    }

    public boolean verify(Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
        transcript.append("m", values.size());

        int n1 = numVars;
        if (!transcript.validateAndAppend("A_I1", proof.getProof().getA_I1())) {
            return false;
        }
        if (!transcript.validateAndAppend("A_O1", proof.getProof().getA_O1())) {
            return false;
        }
        if (!transcript.validateAndAppend("S1", proof.getProof().getS1())) {
            return false;
        }

        randomizedConstraints();

        int n = numVars;
        int n2 = n - n1;
        int nPadded = Utils.nextPowerOf2(n);
        int pad = nPadded - n;

        if (generators.getCapacity() < nPadded) {
            throw new IllegalStateException("Invalid generators length");
        }

        BulletProofGenShare gens = generators.getShare(0);

        transcript.append("A_I2", proof.getProof().getA_I2());
        transcript.append("A_O2", proof.getProof().getA_O2());
        transcript.append("S2", proof.getProof().getS2());

        Scalar y = transcript.challengeScalar("y");
        Scalar z = transcript.challengeScalar("z");

        if (!transcript.validateAndAppend("T_1", proof.getProof().getT1())) {
            return false;
        }
        if (!transcript.validateAndAppend("T_3", proof.getProof().getT3())) {
            return false;
        }
        if (!transcript.validateAndAppend("T_4", proof.getProof().getT4())) {
            return false;
        }
        if (!transcript.validateAndAppend("T_5", proof.getProof().getT5())) {
            return false;
        }
        if (!transcript.validateAndAppend("T_6", proof.getProof().getT6())) {
            return false;
        }

        Scalar u = transcript.challengeScalar("u");
        Scalar x = transcript.challengeScalar("x");

        transcript.append("t_x", proof.getProof().getTx());
        transcript.append("t_x_blinding", proof.getProof().getTxBlinding());
        transcript.append("e_blinding", proof.getProof().getEBlinding());

        Scalar w = transcript.challengeScalar("w");

        VecPoly wp = flattenedConstraints(z);
        List<Scalar> wL = wp.get(0);
        List<Scalar> wR = wp.get(1);
        List<Scalar> wO = wp.get(2);
        List<Scalar> wV = wp.get(3);

        InnerProductProof.IPPVer ippVer = proof.getProof().getIppProof().scalarsVer(nPadded, transcript);
        if (ippVer == null) {
            return false;
        }

        Scalar a = proof.getProof().getIppProof().getA();
        Scalar b = proof.getProof().getIppProof().getB();

        Scalar y_inv = y.invert();

        List<Scalar> exp_y_inv = new ArrayList<>();
        Scalar eyinv = Scalar.ONE;
        for (int i = 0; i < nPadded; i++) {
            exp_y_inv.add(eyinv);
            eyinv = eyinv.multiply(y_inv);
        }

        List<Scalar> yneg_wR = new ArrayList<>();
        for (int i = 0; i < wR.size(); i++) {
            yneg_wR.add(wR.get(i).multiply(exp_y_inv.get(i)));
        }
        for (int i = 0; i < pad; i++) {
            yneg_wR.add(Scalar.ZERO);
        }

        Scalar delta = Utils.innerProduct(yneg_wR.subList(0, n), wL);

        List<Scalar> u_for_g = new ArrayList<>();
        List<Scalar> u_for_h = new ArrayList<>();
        for (int i = 0; i < n1; i++) {
            u_for_g.add(Scalar.ONE);
            u_for_h.add(Scalar.ONE);
        }
        for (int i = 0; i < n2 + pad; i++) {
            u_for_g.add(u);
            u_for_h.add(u);
        }

        List<Scalar> s = ippVer.getS().subList(0, nPadded);
        List<Scalar> g_scalars = new ArrayList<>();
        for (int i = 0; i < yneg_wR.size(); i++) {
            g_scalars.add(u_for_g.get(i).multiply(x.multiply(yneg_wR.get(i)).subtract(a.multiply(s.get(i)))));
        }

        List<Scalar> h_scalars = new ArrayList<>();
        List<Scalar> sinv = new ArrayList<>(ippVer.getS());
        Collections.reverse(sinv);
        for (int i = 0; i < exp_y_inv.size(); i++) {
            Scalar wl = i < wL.size() ? wL.get(i) : Scalar.ZERO;
            Scalar wo = i < wO.size() ? wO.get(i) : Scalar.ZERO;
            h_scalars.add(u_for_h.get(i).multiply(exp_y_inv.get(i).multiply(x.multiply(wl).add(wo).subtract(b.multiply(sinv.get(i)))).subtract(Scalar.ONE)));
        }

        transcript.rnd();

        Scalar r = Utils.randomScalar();

        Scalar xx = x.multiply(x);
        Scalar rxx = r.multiply(xx);
        Scalar xxx = x.multiply(xx);

        List<Scalar> T_scalars = Arrays.asList(r.multiply(x), rxx.multiply(x), rxx.multiply(xx), rxx.multiply(xxx), rxx.multiply(xx).multiply(xx));
        List<CompressedRistretto> T_points = Arrays.asList(proof.getProof().getT1(), proof.getProof().getT3(), proof.getProof().getT4(), proof.getProof().getT5(), proof.getProof().getT6());

        try {
            List<Scalar> scalars = new ArrayList<>();
            scalars.add(xx); // A_O1
            scalars.add(xxx); // S1
            scalars.add(u.multiply(x)); // A_I2
            scalars.add(u.multiply(xx)); // A_O2
            scalars.add(u.multiply(xxx)); // S2
            for (Scalar it : wV) {
                scalars.add(it.multiply(rxx));
            }
            scalars.addAll(T_scalars);
            scalars.add(w.multiply(proof.getProof().getTx().subtract(a.multiply(b))).add(r.multiply(xx.multiply(wp.getC().add(delta)).subtract(proof.getProof().getTx()))));
            scalars.add(Scalar.ZERO.subtract(proof.getProof().getEBlinding()).subtract(r.multiply(proof.getProof().getTxBlinding())));
            scalars.addAll(g_scalars);
            scalars.addAll(h_scalars);
            scalars.addAll(ippVer.getU_sq());
            scalars.addAll(ippVer.getU_inv_sq());

            List<RistrettoElement> points = new ArrayList<>();
            points.add(proof.getProof().getA_O1().decompress());
            points.add(proof.getProof().getS1().decompress());
            points.add(proof.getProof().getA_I2().decompress());
            points.add(proof.getProof().getA_O2().decompress());
            points.add(proof.getProof().getS2().decompress());
            for (CompressedRistretto p : values) {
                points.add(p.decompress());
            }
            for (CompressedRistretto p : T_points) {
                points.add(p.decompress());
            }
            points.add(pedersenCommitment.getB());
            points.add(pedersenCommitment.getBlinding());
            points.addAll(gens.getG(nPadded));
            points.addAll(gens.getH(nPadded));
            for (CompressedRistretto p : proof.getProof().getIppProof().getL()) {
                points.add(p.decompress());
            }
            for (CompressedRistretto p : proof.getProof().getIppProof().getR()) {
                points.add(p.decompress());
            }

            RistrettoElement check = Utils.multiscalarMul(x, scalars, proof.getProof().getA_I1().decompress(), points);

            return RistrettoElement.IDENTITY.equals(check);
        } catch (Exception e) {
            logger.error("Failed check", e);
            return false;
        }
    }

    @Override
    public LRO multiply(LinearCombination left, LinearCombination right) {
        Variable l = Variable.multiplierLeft(numVars);
        Variable r = Variable.multiplierRight(numVars);
        Variable o = Variable.multiplierOutput(numVars);

        numVars++;

        left.append(new Term(l, Utils.MINUS_ONE));
        right.append(new Term(r, Utils.MINUS_ONE));

        constrain(left);
        constrain(right);

        return new LRO(l, r, o);
    }
}
