package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Term {

    private final Variable variable;

    private final Scalar scalar;
}
