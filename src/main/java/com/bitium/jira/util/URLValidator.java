package com.bitium.jira.util;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.reference.DefaultEncoder;
import org.owasp.esapi.reference.DefaultValidator;
import org.owasp.esapi.reference.validation.StringValidationRule;

import java.util.ArrayList;
import java.util.regex.Pattern;

/**
 * Created by dobandom on 1/18/2016.
 */
public class URLValidator extends DefaultValidator {

    public static String getSanitizedUrl(String url) {
        Encoder encoder = new DefaultEncoder(new ArrayList<String>());
        String canonical = url;
        canonical = encoder.canonicalize(canonical).trim();
        int carriageReturn = canonical.indexOf('\r');
        int linefeed = canonical.indexOf('\n');

        if(linefeed >= 0 || carriageReturn >= 0){
            if(linefeed > carriageReturn){
                canonical = canonical.substring(0,linefeed-1);
            } else {
                canonical = canonical.substring(0,carriageReturn-1);
            }
        }
        return canonical;
    }

    public boolean isValidInput(String context, String input, String type, int maxLength, boolean allowNull) {

        Pattern urlPattern = java.util.regex.Pattern.compile("^.*$");
        StringValidationRule validationRule = new StringValidationRule(context, ESAPI.encoder());
        validationRule.addWhitelistPattern( urlPattern );
        validationRule.setMaximumLength(maxLength);
        validationRule.setAllowNull(allowNull);
        validationRule.setValidateInputAndCanonical(false);

        try {
            validationRule.getValid(context,input);
            return true;
        } catch( Exception e ) {
            return false;
        }
    }

}
