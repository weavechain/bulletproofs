
package com.weavechain.zk.bulletproofs;

import com.weavechain.curve25519.RistrettoElement;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class BulletProofGenShare {

    private BulletProofGenerators generators;

    private int share;

    public List<RistrettoElement> getG(int size) {
        List<RistrettoElement> result = generators.getG().get(share);
        return result.size() > size ? result.subList(0, size) : result;
    }

    public List<RistrettoElement> getH(int size) {
        List<RistrettoElement> result = generators.getH().get(share);
        return result.size() > size ? result.subList(0, size) : result;
    }
}
