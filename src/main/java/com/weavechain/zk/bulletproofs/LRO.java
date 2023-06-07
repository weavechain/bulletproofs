package com.weavechain.zk.bulletproofs;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class LRO {

    private final Variable left;

    private final Variable right;

    private final Variable output;
}