package com.weavechain.zk.bulletproofs;

import com.weavechain.ec.ECPoint;
import com.weavechain.ec.Scalar;
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
        return BulletProofs.getFactory().fromBits(r);
    }

    public static Scalar scalar(Integer value) {
        return scalar(Long.valueOf(value));
    }

    public static Scalar scalar(Long value) {
        ByteBuffer buffer = ByteBuffer.allocate(32);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(value);
        buffer.flip();
        return BulletProofs.getFactory().fromBits(buffer.array());
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

    public static ECPoint multiscalarMul(Scalar s1, List<Scalar> s2, List<Scalar> s3, ECPoint p1, List<ECPoint> p2, List<ECPoint> p3) {
        return BulletProofs.getFactory().multiscalarMulOpt(s1, s2, s3, p1, p2, p3);
    }

    public static ECPoint multiscalarMul(Scalar s1, List<Scalar> s2, ECPoint p1, List<ECPoint> p2) {
        return BulletProofs.getFactory().multiscalarMulOpt(s1, s2, null, p1, p2, null);
    }

    public static ECPoint multiscalarMul(Scalar s1, Scalar s2, ECPoint p1, ECPoint p2) {
        return BulletProofs.getFactory().mulOptimized(s1, s2, p1, p2);
    }

    public static Scalar innerProduct(List<Scalar> a, List<Scalar> b) {
        if (a.size() == b.size()) {
            Scalar result = BulletProofs.getFactory().zero();
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
        return BulletProofs.getFactory().fromBits(dest);
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
            return BulletProofs.getFactory().fromBits(Base58.decode(json.getAsString()));
        }
    }
}
