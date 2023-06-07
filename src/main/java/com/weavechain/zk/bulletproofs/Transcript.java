package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.CompressedRistretto;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Transcript {

    private ByteArrayOutputStream transcript = new ByteArrayOutputStream();

    public void append(String key, String value) {
        transcript.write('s');
        writeString(key);
        writeString(value);
    }

    public void append(String key, long value) {
        transcript.write('l');
        writeString(key);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(value);
        transcript.writeBytes(buffer.array());
    }

    public void append(String key, Scalar value) {
        transcript.write('S');
        writeString(key);
        transcript.writeBytes(value.toByteArray());
    }

    public void append(String key, CompressedRistretto value) {
        transcript.write('P');
        writeString(key);
        transcript.writeBytes(value.toByteArray());
    }

    public void phase1() {
        writeString("dom-sep");
        writeString("r1cs-1phase");
    }

    public void phase2() {
        writeString("dom-sep");
        writeString("r1cs-2phase");
    }

    public boolean validateAndAppend(String key, CompressedRistretto value) {
        try {
            if (RistrettoElement.IDENTITY.equals(value.decompress())) {
                return false;
            } else {
                append(key, value);
                return true;
            }
        } catch (InvalidEncodingException e) {
            return false;
        }
    }

    private void writeString(String key) {
        byte[] k = key.getBytes(StandardCharsets.UTF_8);
        transcript.write(k.length);
        transcript.writeBytes(k);
    }

    public void rnd() {
        byte[] randomness = Utils.randomScalar().toByteArray();
        transcript.write(randomness.length);
        transcript.writeBytes(randomness);
    }

    public Scalar challengeScalar(String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-512");
            md.update(transcript.toByteArray());
            byte[] digest = md.digest();

            return Scalar.fromBytesModOrderWide(digest);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }
}
