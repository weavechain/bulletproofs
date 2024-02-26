package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Getter
@AllArgsConstructor
public class LinearCombination {

    private final List<Term> terms = new ArrayList<>();

    public static LinearCombination from(Variable v) {
        return LinearCombination.from(new Term(v, BulletProofs.getFactory().one()));
    }

    public static LinearCombination from(BigInteger v) {
        return from(v, false);
    }

    public static LinearCombination from(BigInteger v, boolean invert) {
        Scalar s = Utils.scalarFromBigInteger(v.abs());
        if (invert) {
            s = s.invert();
        }
        return v.signum() >= 0 ? LinearCombination.from(new Term(Variable.ONE, s)) : LinearCombination.from(new Term(Variable.ONE_MINUS, s));
    }

    public static LinearCombination from(Scalar s) {
        return LinearCombination.from(new Term(Variable.ONE, s));
    }

    public static LinearCombination from(Term t) {
        return new LinearCombination().append(t);
    }

    public static LinearCombination from(Collection<Term> terms) {
        return new LinearCombination().appendAll(terms);
    }

    public LinearCombination append(Term t) {
        terms.add(t);
        return this;
    }

    public LinearCombination appendAll(Collection<Term> terms) {
        this.terms.addAll(terms);
        return this;
    }

    public LinearCombination add(LinearCombination other) {
        terms.addAll(other.getTerms());
        return this;
    }

    public LinearCombination sub(LinearCombination other) {
        for (Term t : other.getTerms()) {
            terms.add(new Term(t.getVariable(), BulletProofs.getFactory().zero().subtract(t.getScalar())));
        }
        return this;
    }

    @Override
    public LinearCombination clone() {
        return LinearCombination.from(terms);
    }
}
