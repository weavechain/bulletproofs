
package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class BulletProofGenShare {

    private BulletProofGenerators generators;

    private int share;

    public List<ECPoint> getG(int size) {
        List<ECPoint> result = generators.getG().get(share);
        return result.size() > size ? result.subList(0, size) : result;
    }

    public List<ECPoint> getH(int size) {
        List<ECPoint> result = generators.getH().get(share);
        return result.size() > size ? result.subList(0, size) : result;
    }
}
