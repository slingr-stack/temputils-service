package io.slingr.services.temputils;

import io.slingr.services.Service;
import io.slingr.services.framework.annotations.*;
import io.slingr.services.temputils.logic.CryptoUtils;
import io.slingr.services.services.AppLogs;
import io.slingr.services.utils.Json;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * <p>Temporary Utilities
 *
 * <p>Created by dgaviola on 10/14/23.
 */
@SlingrService(name = "temputils")
public class Temputils extends Service {
    private static final Logger logger = LoggerFactory.getLogger(Temputils.class);

    @ApplicationLogger
    private AppLogs appLogger;

    @ServiceProperty
    private String token;

    @ServiceConfiguration
    private Json configuration;

    @ServiceFunction(name = "hs256")
    public Json hs256(Json data) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        String secret = data.string("secret");
        String message = data.string("message");
        Json res = Json.map();
        String hash = CryptoUtils.getInstance().hs256(message, secret);
        res.string("hash", hash);
        return res;
    }
}
