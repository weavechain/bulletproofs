package com.weavechain.zk.bulletproofs;

import cafe.cryptography.curve25519.RistrettoElement;
import cafe.cryptography.curve25519.Scalar;
import com.google.gson.*;
import org.bitcoinj.base.Base58;

import java.lang.reflect.Type;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

public class Utils {

    public static final Scalar MINUS_ONE = Scalar.ZERO.subtract(Scalar.ONE);

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    private static final ThreadLocal<Gson> gson = ThreadLocal.withInitial(Utils::createGson);

    public static SecureRandom random() {
        return RANDOM.get();
    }

    public static GsonBuilder createGsonBuilder() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.setLongSerializationPolicy(LongSerializationPolicy.STRING);
        gsonBuilder.setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE);
        gsonBuilder.registerTypeAdapter(Scalar.class, new ScalarSerializer());
        gsonBuilder.disableHtmlEscaping();
        return gsonBuilder
                .serializeSpecialFloatingPointValues();
    }

    public static Gson createGson() {
        return createGsonBuilder()
                .create();
    }

    public static Gson getGson() {
        return gson.get();
    }

    public static Scalar randomScalar() {
        byte[] r = new byte[32];
        random().nextBytes(r);
        return Scalar.fromBits(r);
    }

    public static Scalar scalar(Integer value) {
        return scalar(Long.valueOf(value));
    }

    public static Scalar scalar(Long value) {
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(value);
        buffer.flip();
        return Scalar.fromBits(buffer.array());
    }

    public static Long scalarToLong(Scalar value) {
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(value.toByteArray());
        buffer.flip();
        return buffer.getLong();
    }

    public static Scalar scalar(BigInteger value) {
        return Utils.scalarFromBigInteger(value);
    }

    public static RistrettoElement multiscalarMul(Scalar s1, List<Scalar> s2, List<Scalar> s3, RistrettoElement p1, List<RistrettoElement> p2, List<RistrettoElement> p3) {
        RistrettoElement res = p1.multiply(s1);

        if (s2 != null && p2 != null && s2.size() == p2.size()) {
            for (int i = 0; i < s2.size(); i++) {
                res = res.add(p2.get(i).multiply(s2.get(i)));
            }
        }

        if (s3 != null && p3 != null && s3.size() == p3.size()) {
            for (int i = 0; i < s3.size(); i++) {
                res = res.add(p3.get(i).multiply(s3.get(i)));
            }
        }

        return res;
    }

    public static RistrettoElement multiscalarMul(Scalar s1, List<Scalar> s2, RistrettoElement p1, List<RistrettoElement> p2) {
        return multiscalarMul(s1, s2, null, p1, p2, null);
    }

    public static RistrettoElement multiscalarMul(Scalar s1, Scalar s2, RistrettoElement p1, RistrettoElement p2) {
        return p1.multiply(s1).add(p2.multiply(s2));
    }

    public static Scalar innerProduct(List<Scalar> a, List<Scalar> b) {
        if (a.size() == b.size()) {
            Scalar result = Scalar.ZERO;
            for (int i = 0; i < a.size(); i++) {
                result = result.add(a.get(i).multiply(b.get(i)));
            }
            return result;
        } else {
            return null;
        }
    }

    public static int nextPowerOf2(int value) {
        return Math.max(1, Integer.highestOneBit(value - 1) << 1);
    }

    public static Scalar scalarFromBigInteger(BigInteger value) {
        byte[] data = value.toByteArray();
        byte[] dest = new byte[32];
        int start = Math.max(0, data.length - 32);
        for (int j = start; j < data.length; j++) {
            dest[j - start] = data[data.length - 1 + start - j];
        }
        return Scalar.fromBits(dest);
    }

    public static BigInteger toBigInteger(Scalar scalar) {
        byte[] data = scalar.toByteArray();
        byte[] dest = new byte[32];
        for (int j = 0; j < data.length; j++) {
            dest[j] = data[data.length - 1 - j];
        }
        return new BigInteger(dest);
    }

    public static String toString(byte[] arr) {
        int[] a = new int[arr.length];
        for (int i = 0; i < arr.length; i++) {
            a[i] = arr[i] < 0 ? 256 + arr[i] : arr[i];
        }
        return Arrays.toString(a);
    }


    public static class ScalarSerializer implements JsonSerializer<Scalar>, JsonDeserializer<Scalar> {
        public JsonElement serialize(Scalar data, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(Base58.encode(data.toByteArray()));
        }

        public Scalar deserialize(JsonElement json, Type typeOfSrc, JsonDeserializationContext context) {
            return Scalar.fromBits(Base58.decode(json.getAsString()));
        }
    }
}
