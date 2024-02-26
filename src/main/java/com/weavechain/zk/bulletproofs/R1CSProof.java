package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import com.weavechain.ec.Scalar;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;

@Getter
@AllArgsConstructor
public class R1CSProof {

    // Commitment to the values of input wires in the first phase.
    private final ECPoint A_I1;

    // Commitment to the values of output wires in the first phase.
    private final ECPoint A_O1;

    // Commitment to the blinding factors in the first phase.
    private final ECPoint S1;

    // Commitment to the values of input wires in the second phase.
    private final ECPoint A_I2;

    // Commitment to the values of output wires in the second phase.
    private final ECPoint A_O2;

    // Commitment to the blinding factors in the second phase.
    private final ECPoint S2;

    // Commitment to the t_1 coefficient of t(x)
    private final ECPoint T1;

    // Commitment to the t4 coefficient of t(x)
    private final ECPoint T3;

    // Commitment to the t_4 coefficient of t(x)
    private final ECPoint T4;

    // Commitment to the t_5 coefficient of t(x)
    private final ECPoint T5;

    // Commitment to the t_6 coefficient of t(x)
    private final ECPoint T6;

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
        ECPoint A_I1 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint A_O1 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint S1 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint A_I2 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint A_O2 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint S2 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint T1 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint T3 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint T4 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint T5 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        ECPoint T6 = BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32));
        Scalar tx = BulletProofs.getFactory().fromBits(unpacker.readPayload(32));
        Scalar txBlinding = BulletProofs.getFactory().fromBits(unpacker.readPayload(32));
        Scalar eBlinding = BulletProofs.getFactory().fromBits(unpacker.readPayload(32));

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
