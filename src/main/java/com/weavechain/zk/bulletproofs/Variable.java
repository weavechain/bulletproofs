package com.weavechain.zk.bulletproofs;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Variable {

    public static final Variable ONE = new Variable(VariableType.one, 1);

    private final VariableType type;

    private final long value;

    public static Variable from(long value) {
        return new Variable(VariableType.one, value);
    }

    public int getIndex() {
        return (int)value;
    }

    public static Variable multiplierLeft(int index) {
        return new Variable(VariableType.multiplier_left, index);
    }

    public static Variable multiplierRight(int index) {
        return new Variable(VariableType.multiplier_right, index);
    }

    public static Variable multiplierOutput(int index) {
        return new Variable(VariableType.multiplier_output, index);
    }
}
