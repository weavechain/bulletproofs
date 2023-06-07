package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;

@Getter
@AllArgsConstructor
public class R1CSProof {

    // Commitment to the values of input wires in the first phase.
    private final CompressedRistretto A_I1;

    // Commitment to the values of output wires in the first phase.
    private final CompressedRistretto A_O1;

    // Commitment to the blinding factors in the first phase.
    private final CompressedRistretto S1;

    // Commitment to the values of input wires in the second phase.
    private final CompressedRistretto A_I2;

    // Commitment to the values of output wires in the second phase.
    private final CompressedRistretto A_O2;

    // Commitment to the blinding factors in the second phase.
    private final CompressedRistretto S2;

    // Commitment to the t_1 coefficient of t(x)
    private final CompressedRistretto T1;

    // Commitment to the t4 coefficient of t(x)
    private final CompressedRistretto T3;

    // Commitment to the t_4 coefficient of t(x)
    private final CompressedRistretto T4;

    // Commitment to the t_5 coefficient of t(x)
    private final CompressedRistretto T5;

    // Commitment to the t_6 coefficient of t(x)
    private final CompressedRistretto T6;

    // Evaluation of the polynomial t(x) at the challenge point x
    private final Scalar tx;

    // Blinding factor for the synthetic commitment to t(x)
    private final Scalar txBlinding;

    // Blinding factor for the synthetic commitment to the inner-product arguments
    private final Scalar eBlinding;

    /// Proof data for the inner-product argument.
    private final InnerProductProof ippProof;

    public void pack(MessageBufferPacker packer) throws IOException {
        packer.writePayload(A_I1.toByteArray());
        packer.writePayload(A_O1.toByteArray());
        packer.writePayload(S1.toByteArray());
        packer.writePayload(A_I2.toByteArray());
        packer.writePayload(A_O2.toByteArray());
        packer.writePayload(S2.toByteArray());
        packer.writePayload(T1.toByteArray());
        packer.writePayload(T3.toByteArray());
        packer.writePayload(T4.toByteArray());
        packer.writePayload(T5.toByteArray());
        packer.writePayload(T6.toByteArray());
        packer.writePayload(tx.toByteArray());
        packer.writePayload(txBlinding.toByteArray());
        packer.writePayload(eBlinding.toByteArray());
        ippProof.pack(packer);
    }

    public static R1CSProof unpack(MessageUnpacker unpacker) throws IOException {
        CompressedRistretto A_I1 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto A_O1 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto S1 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto A_I2 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto A_O2 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto S2 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto T1 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto T3 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto T4 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto T5 = new CompressedRistretto(unpacker.readPayload(32));
        CompressedRistretto T6 = new CompressedRistretto(unpacker.readPayload(32));
        Scalar tx = Scalar.fromBits(unpacker.readPayload(32));
        Scalar txBlinding = Scalar.fromBits(unpacker.readPayload(32));
        Scalar eBlinding = Scalar.fromBits(unpacker.readPayload(32));

        InnerProductProof ippProof = InnerProductProof.unpack(unpacker);

        return new R1CSProof(
                A_I1,
                A_O1,
                S1,
                A_I2,
                A_O2,
                S2,
                T1,
                T3,
                T4,
                T5,
                T6,
                tx,
                txBlinding,
                eBlinding,
                ippProof
        );
    }
}
