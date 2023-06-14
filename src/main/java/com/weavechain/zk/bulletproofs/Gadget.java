package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.Scalar;

public interface Gadget<T extends GadgetParams> {

    GadgetType getType();

    boolean isBatchProof();

    boolean isNumericInput();

    boolean isMultiColumn();

    GadgetParams unpackParams(String params, Object value);

    Proof generate(Object value, T params, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators);

    boolean verify(T params, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators);
}
