package com.efx.pet.service.encryption.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class URIEncoder {

    public static String encodeURI(String offerCode) throws UnsupportedEncodingException {
        return URLEncoder.encode(offerCode, StandardCharsets.UTF_8.toString());
    }


}
