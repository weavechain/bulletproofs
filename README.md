## Bulletproofs

A pure Java implementation of Bulletproofs using Ristretto.

Bulletproofs are short non-interactive zero-knowledge proofs that require no trusted setup. 

Based on the [Rust Bulletproofs implementation](https://github.com/dalek-cryptography/bulletproofs) from dalek-cryptography

[Read More about Bulletproofs](https://crypto.stanford.edu/bulletproofs/)

[Paper](https://eprint.iacr.org/2017/1066.pdf) 
(B. Bünz, J. Bootle, D. Boneh, A. Poelstra, P. Wuille, and G. Maxwell.
Bulletproofs: Short proofs for confidential transactions and more. 2018
IEEE Symposium on Security and Privacy (SP), pages 315–334, May 2018)

See also the Java [Bulletproofs Gadgets](https://github.com/weavechain/bulletproofs-gadgets) library

### Why Java?

Java is one of the languages of choice for Fintech and Banking software. At the same time the use of advanced privacy preserving technologies is lagging behind in these sectors. One of the reasons could be that the libraries for advanced cryptographic primitives are not readily available, and this is our contribution to gradually close the gap.

### Gradle Groovy DSL
```
implementation 'com.weavechain:bulletproofs:1.0.6'
```

### Gradle Kotlin DSL

```
implementation("com.weavechain:bulletproofs:1.0.6")
```

#### Apache Maven

```xml
<dependency>
  <groupId>com.weavechain</groupId>
  <artifactId>bulletproofs</artifactId>
  <version>1.0.6</version>
</dependency>
```

### Warning

This bulletproofs library has been partially audited and is provided as-is, we make no guarantees or warranties to its safety, security and reliability.

### Usage

Sample Range Proof (partially based on a [Rust implementation](https://github.com/lovesh/bulletproofs-r1cs-gadgets))

```java
private static Proof generateRangeProof(long value, long min, long max, int bitsize, Scalar rnd, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
    long a = value - min;
    long b = max - value;

    List<CompressedRistretto> commitments = new ArrayList<>();

    Transcript transcript = new Transcript();
    Prover prover = new Prover(transcript, pedersenCommitment);

    Commitment vComm = prover.commit(Utils.scalar(value), rnd != null ? rnd : Utils.randomScalar());
    Allocated av = new Allocated(vComm.getVariable(), value);
    commitments.add(vComm.getCommitment());

    Commitment aComm = prover.commit(Utils.scalar(a), Utils.randomScalar());
    Allocated aa = new Allocated(aComm.getVariable(), a);
    commitments.add(aComm.getCommitment());

    Commitment bComm = prover.commit(Utils.scalar(b), Utils.randomScalar());
    Allocated ab = new Allocated(bComm.getVariable(), b);
    commitments.add(bComm.getCommitment());

    if (checkBound(prover, av, aa, ab, min, max, bitsize)) {
        return new Proof(prover.prove(generators), commitments);
    } else {
        return null;
    }
}

private static boolean verifyRangeProof(long min, long max, int bitsize, Proof proof, PedersenCommitment pedersenCommitment, BulletProofGenerators generators) {
    Transcript transcript = new Transcript();
    Verifier verifier = new Verifier(transcript);

    Variable v = verifier.commit(proof.getCommitment(0));
    Allocated av = new Allocated(v, null);

    Variable a = verifier.commit(proof.getCommitment(1));
    Allocated aa = new Allocated(a, null);

    Variable b = verifier.commit(proof.getCommitment(2));
    Allocated ab = new Allocated(b, null);

    if (checkBound(verifier, av, aa, ab, min, max, bitsize)) {
        return verifier.verify(proof, pedersenCommitment, generators);
    } else {
        return false;
    }
}

private static boolean checkBound(ConstraintSystem cs, Allocated v, Allocated a, Allocated b, long min, long max, Integer bitsize) {
    cs.constrain(LinearCombination.from(v.getVariable()).sub(LinearCombination.from(Utils.scalar(min))).sub(LinearCombination.from(a.getVariable())));
    cs.constrain(LinearCombination.from(Utils.scalar(max)).sub(LinearCombination.from(v.getVariable())).sub(LinearCombination.from(b.getVariable())));

    cs.constrainLCWithScalar(LinearCombination.from(a.getVariable()).add(LinearCombination.from(b.getVariable())), Utils.scalar(max - min));

    return verifyIsPositive(cs, a, bitsize) && verifyIsPositive(cs, b, bitsize);
}

private static boolean verifyIsPositive(ConstraintSystem cs, Allocated variable, int bitsize) {
    List<Term> constraints = new ArrayList<>();

    constraints.add(new Term(variable.getVariable(), BulletProofs.getFactory().minus_one()));

    Scalar exp2 = BulletProofs.getFactory().one();
    for (int i = 0; i < bitsize; i++) {
        long bit = ((variable.getAssignment() != null ? variable.getAssignment() : 0L) >> i) & 1;
        LRO lro = cs.allocateMultiplier(Utils.scalar(1 - bit), Utils.scalar(bit));

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(LinearCombination.from(lro.getOutput()));

        // Enforce that a = 1 - b, so they both are 1 or 0
        cs.constrain(LinearCombination.from(lro.getLeft()).add(LinearCombination.from(lro.getRight()).sub(LinearCombination.from(BulletProofs.getFactory().one()))));

        constraints.add(new Term(lro.getRight(), exp2));
        exp2 = exp2.add(exp2);
    }

    // Enforce that -v + Sum(b_i * 2^i, i = 0..n-1) = 0 => Sum(b_i * 2^i, i = 0..n-1) = v
    LinearCombination lc = null;
    for (Term t : constraints) {
        lc = lc == null ? LinearCombination.from(t) : lc.add(LinearCombination.from(t));
    }
    cs.constrain(lc);

    return true;
}

public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
    long value = 16L;

    long min = 10;
    long max = 100;
    int bitsize = 31;

    PedersenCommitment pc = PedersenCommitment.getDefault();
    BulletProofGenerators bg1 = new BulletProofGenerators(128, 1);

    Scalar rnd = Utils.randomScalar();
    Proof proof = generateRangeProof(value, min, max, bitsize, rnd, pc, bg1);

    Proof proof2 = Proof.deserialize(proof.serialize());

    BulletProofGenerators bg2 = new BulletProofGenerators(128, 1);

    boolean match = verifyRangeProof(min, max, bitsize, proof2, pc, bg2);
    System.out.println(match ? "Success" : "Fail");
}
```

#### Weavechain

Weavechain is a Layer-0 for Data, adding Web3 Security and Data Economics to data stored in private vaults in any of the traditional databases.

Read more on [https://docs.weavechain.com](https://docs.weavechain.com)