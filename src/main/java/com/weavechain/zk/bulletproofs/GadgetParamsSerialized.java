package com.weavechain.zk.bulletproofs;

import java.lang.reflect.Modifier;

public abstract class GadgetParamsSerialized implements GadgetParams {

    public String serializeNoValue() {
        return Utils.getGson().toJson(this);
    }

    public String serialize() {
        return Utils.createGsonBuilder()
                .excludeFieldsWithModifiers(Modifier.STATIC)
                .create()
                .toJson(this);
    }
}
