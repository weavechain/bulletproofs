package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class VecPoly {

    @Getter
    private Scalar c;

    private final List<List<Scalar>> coefficients = new ArrayList<>();

    public VecPoly(int degree, int size) {
        for (int i = 0; i <= degree; i++) {
            coefficients.add(new ArrayList<>(Collections.nCopies(size, Scalar.ZERO)));
        }
    }

    public VecPoly(Scalar c) {
        this.c = c;
    }

    public void add(List<Scalar> w) {
        coefficients.add(w);
    }

    public List<Scalar> get(int index) {
        return coefficients.get(index);
    }

    public Poly spInnerProduct(VecPoly other) {
        Scalar t1 = Utils.innerProduct(this.get(1), other.get(0));
        Scalar t2 = Utils.innerProduct(this.get(1), other.get(1)).add(Utils.innerProduct(this.get(2), other.get(0)));
        Scalar t3 = Utils.innerProduct(this.get(2), other.get(1)).add(Utils.innerProduct(this.get(3), other.get(0)));
        Scalar t4 = Utils.innerProduct(this.get(1), other.get(3)).add(Utils.innerProduct(this.get(3), other.get(1)));
        Scalar t5 = Utils.innerProduct(this.get(2), other.get(3));
        Scalar t6 = Utils.innerProduct(this.get(3), other.get(3));

        return new Poly(Scalar.ZERO, t1, t2, t3, t4, t5, t6);
    }

    public List<Scalar> at(Scalar x) {
        if (coefficients.size() > 0) {
            int n = coefficients.get(0).size();
            List<Scalar> res = new ArrayList<>(Collections.nCopies(n, Scalar.ZERO));

            for (int i = 0; i < n; i++) {
                Scalar val = coefficients.get(0).get(i);

                Scalar cp = Scalar.ONE;
                for (int j = 1; j < coefficients.size(); j++) {
                    cp = cp.multiply(x);
                    val = coefficients.get(j).get(i).multiplyAndAdd(cp, val);
                }
                res.set(i, val);
            }

            return res;
        } else {
            return null;
        }
    }
}