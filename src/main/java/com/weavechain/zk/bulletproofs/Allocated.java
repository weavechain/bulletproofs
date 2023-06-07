package com.weavechain.zk.bulletproofs;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Allocated {

    private final Variable variable;

    private final Long assignment;
}
