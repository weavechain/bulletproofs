package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.CompressedRistretto;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Commitment {

    private final CompressedRistretto commitment;

    private final Variable variable;
}
