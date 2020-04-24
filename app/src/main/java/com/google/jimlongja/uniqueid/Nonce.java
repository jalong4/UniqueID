package com.google.jimlongja.uniqueid;

import com.google.gson.annotations.SerializedName;

class Nonce {
    @SerializedName("V")
    String value;
    @SerializedName(value = "E")
    long expirationEpoc;

    Nonce(String value, long expirationEpoc) {
        this.value = value;
        this.expirationEpoc = expirationEpoc;
    }
}
