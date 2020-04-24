package com.google.jimlongja.uniqueid;

import com.google.gson.annotations.SerializedName;

class Challenge {

    @SerializedName("N")
    Nonce nonce;
    @SerializedName("S")
    String signiture;

    Challenge(Nonce nonce, String signiture) {
        this.nonce = nonce;
        this.signiture = signiture;
    }
}

