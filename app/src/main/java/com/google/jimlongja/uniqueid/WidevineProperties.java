package com.google.jimlongja.uniqueid;

import android.media.MediaDrm;

import java.util.UUID;

public class WidevineProperties {
    private static final UUID WIDEVINE_UUID = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
    private MediaDrm mMediaDrm = null;

    private String mSystemID;
    private String mSPOID;

    public WidevineProperties() {
        mSystemID = getWidevineSystemId();
        mSPOID = getWidevineSPOID();
    }

    public String getSystemID() {
        return mSystemID;
    }

    public String getSPOID() {
        return mSPOID;
    }

    @Override
    public String toString() {
        return "WidevineProperties{" +
                "System ID ='" + mSystemID + '\'' +
                ", SPOID ='" + mSPOID + '\'' +
                '}';
    }

    private MediaDrm getDrmInfo() {

        MediaDrm mediaDrm = null;
        try {
            mediaDrm = new MediaDrm(WIDEVINE_UUID);
        } catch (Exception e) {
            throw new Error("Unexpected exception ", e);
        } finally {
            if (mMediaDrm != null) {
                mMediaDrm.close();
            }
        }

        return mediaDrm;

    }

    private String getWidevineSystemId() {
        return getDrmInfo().getPropertyString("systemId");
    }

    private String getWidevineSPOID() {
        return bytesToHex(getDrmInfo().getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID));
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
