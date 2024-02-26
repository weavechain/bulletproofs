package com.weavechain.zk.bulletproofs;

import com.github.aelstad.keccakj.fips202.Shake256;
import com.weavechain.ec.ECPoint;
import lombok.Getter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Getter
public class BulletProofGenerators {

    private final int capacity; //TODO: compute generators size automatically?

    private final int parties;

    private final List<List<ECPoint>> g = new ArrayList<>();

    private final List<List<ECPoint>> h = new ArrayList<>();

    public BulletProofGenerators(int capacity, int parties) throws IOException {
        this.capacity = capacity;
        this.parties = parties;

        for (int i = 0; i < parties; i++) {
            byte[] label = new byte[5];
            label[1] = (byte)(i & 0xFF);
            label[2] = (byte)((i >> 8) & 0xFF);
            label[3] = (byte)((i >> 16) & 0xFF);
            label[4] = (byte)((i >> 24) & 0xFF);

            label[0] = 'G';
            Shake256 gDigest = new Shake256();
            gDigest.getAbsorbStream().write("GeneratorsChain".getBytes(StandardCharsets.UTF_8));
            gDigest.getAbsorbStream().write(label);

            byte[] gpoints = new byte[32 * capacity];
            gDigest.getSqueezeStream().read(gpoints);
            gDigest.reset();

            label[0] = 'H';
            Shake256 hDigest = new Shake256();
            hDigest.getAbsorbStream().write("GeneratorsChain".getBytes(StandardCharsets.UTF_8));
            hDigest.getAbsorbStream().write(label);

            byte[] hpoints = new byte[32 * capacity];
            hDigest.getSqueezeStream().read(hpoints);
            hDigest.reset();

            List<ECPoint> ge = new ArrayList<>();
            List<ECPoint> he = new ArrayList<>();
            for (int j = 0; j < capacity; j++) {
                ge.add(BulletProofs.getFactory().fromUniformBytes(Arrays.copyOfRange(gpoints, j * 32, j * 32 + 32)));
                he.add(BulletProofs.getFactory().fromUniformBytes(Arrays.copyOfRange(hpoints, j * 32, j * 32 + 32)));
            }

            g.add(ge);
            h.add(he);
        }
    }

    public BulletProofGenShare getShare(int share) {
        return new BulletProofGenShare(this, share);
    }
}
