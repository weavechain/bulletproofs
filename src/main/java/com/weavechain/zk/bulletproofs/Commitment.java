package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Commitment {

    private final ECPoint commitment;

    private final Variable variable;
}
