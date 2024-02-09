package com.weavechain.zk.bulletproofs;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class Allocated {

    private final Variable variable;

    private final BigInteger assignment;
}
