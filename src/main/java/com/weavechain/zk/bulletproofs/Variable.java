package com.weavechain.zk.bulletproofs;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class Variable {

    public static final Variable ONE = new Variable(VariableType.one, BigInteger.ONE);

    public static final Variable ONE_MINUS = new Variable(VariableType.one_minus, BigInteger.ONE.negate());

    private final VariableType type;

    private final BigInteger value;

    public static Variable from(BigInteger value) {
        return new Variable(VariableType.one, value);
    }

    public static Variable from(long value) {
        return new Variable(VariableType.one, BigInteger.valueOf(value));
    }

    public int getIndex() {
        return value.intValue();
    }

    public static Variable multiplierLeft(int index) {
        return new Variable(VariableType.multiplier_left, BigInteger.valueOf(index));
    }

    public static Variable multiplierRight(int index) {
        return new Variable(VariableType.multiplier_right, BigInteger.valueOf(index));
    }

    public static Variable multiplierOutput(int index) {
        return new Variable(VariableType.multiplier_output, BigInteger.valueOf(index));
    }
}
