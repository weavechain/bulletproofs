package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.msgpack.core.MessageBufferPacker;
import org.msgpack.core.MessagePack;
import org.msgpack.core.MessageUnpacker;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Getter
@AllArgsConstructor
public class Proof {

    private final R1CSProof proof;

    private final List<ECPoint> commitments;

    public ECPoint getCommitment(int i) {
        return commitments.get(i);
    }


    public static Proof deserialize(byte[] data) throws IOException {
        MessageUnpacker unpacker = MessagePack.newDefaultUnpacker(data);
        int len = unpacker.unpackInt();

        List<ECPoint> commitments = new ArrayList<>();
        for (int i = 0; i < len; i++) {
            commitments.add(BulletProofs.getFactory().fromCompressed(unpacker.readPayload(32)));
        }
        R1CSProof proof = R1CSProof.unpack(unpacker);
        unpacker.close();

        return new Proof(proof, commitments);
    }

    public byte[] serialize() throws IOException {
        MessageBufferPacker packer = MessagePack.newDefaultBufferPacker();
        packer.packInt(commitments.size());

        for (ECPoint p : commitments) {
            packer.writePayload(p.toByteArray());
        }
        proof.pack(packer);
        packer.close();

        return packer.toMessageBuffer().toByteArray();
    }

}
