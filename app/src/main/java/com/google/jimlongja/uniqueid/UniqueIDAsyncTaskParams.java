package com.google.jimlongja.uniqueid;

import android.content.Context;

class UniqueIDAsyncTaskParams {
    UniqueIDAsyncTaskParams(Context context,
                            String challenge,
                            UniqueIDAsyncTaskInterface callback) {
        this.context = context;
        this.challenge = challenge;
        this.callback = callback;
    }
    Context context;
    String challenge;
    UniqueIDAsyncTaskInterface callback;
}
