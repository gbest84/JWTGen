
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.Test;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;


public class JwtRsaTest {

    @Test
    public void testJWTWithRsa() {
        String pvk = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2UAPkhM+VQhkJ0yL6KEaWGRzEIT7aSSyutyUDdn8ZRtnjTBJQLWqhP13gBtbysMUk66xVA6QPgxxTEObcgZ9f3Nvy8q6oJ6E3PoCIB/9Vmn+j6T/GD50kMReV/qrpOiS9t7g/zxcuax7TZNzKcvMNDc6IXp8GhLLnDtOictKVqga6F6qihi61hlN9RatP+tfKNcpeE7gS0uA75bmiIQurBhPYycD9LNu5feirrhYJ8C5vd9QZXJUtt3LIh1akgXWNMaHfOmhJ299A1p1ZHu/FDByIj1ywTk15AlXP70h3N2a8cgfmzyE0elIAPE61laK9LlwG/+IKan+4Q5AuOT/FAgMBAAECggEAEIwIImpUfe9THvNpIgvcRjzOwdVjo0PPeKcaRqtvYz+tQIZTxi+tFSgPcOkmAr59EjoKuOec8SR9AmQPFBX2vWhqFS2mIRCBvyYe29nf+KjOa3Xc6jDaGiITijNkV0lF8us1H6N/7uBdmqG1sXFH8pgddf6ij+Ck7ThJCJ5D0z4FB2sO7rCGJxKcmPC7xde2rHOOy/Ek4chTYoGrU3pRzScPz75hUP0f7YFPbbEAs4QmkAmgRmYvbLvDaVc+MUOzgV94CCARCUrVEioaSNZz/WWMTKx7igLOrl9TWmFO8Fbp7x1Ab4zW5zPg6nI+FvhadKIst8kzC06dqO61l6KdiQKBgQD4ZmbcPln0uD1vZLNCWLHfH818FNc3eIct+2UwP83DIYCyOuECVIH5oofAC8mmdtGQ5Y367OZrGDUN1Y0C2sDPlOPqTDaZKt2uIZ44M0mWV92+pt+dfwOeKoV11gEm4c49wwB4uiDp1FcBtnQvAQmsrYQgPAg9z5o7+2m+4pPzzQKBgQC74/trNetwluslrvbZ6mKRQpRSp4jsdXJDBF13zrtANeeCWwJhye10oMezwVMwCgojAHbDK2Mo9TDJzcwXqfO+glO/GhMBV3FYeC7PhLi/UHklt+f3dv+IS7jp7kKOyS5Qxb9DEhI/xB/SjMNroCu1zmR2/j1hhVDiexV3i/Tz2QKBgAVjw2uX9r+2l66pErKn1gQvXngIw7qyZMx8ne90EvTe7znuyR8R0lgmTKfAGboA7f8k2/XL2hwMxGnubkbXlENsyZ011iFwqqqylApIIpqegXM3j7aNIPj3lzm9UP0U/TKd3o7ACyLHtrOUz+SNMzaJ9Un1w4AD1ybiB6NaqzcpAoGBAJ7XvVzEx9d2bzN7eEuAQHZHkDdUVYh6Pe/0R8SarGk7aQ4mPJxJZwsbRdlszhQl2K4AnWagToN4zhc9eZZj4qGjcoNz2q9eqn89k21y6fErak/96wilvKAQTDLQb8pgwFwe4XQlWfI4ryKESE27qlhYNUz34RKJ73iYz+wyERL5AoGAY4Brkpfbaa/1rRYkbP854GdMI5hgoXbM53yTFt5m9Zsry2QMddvn5wUJF91PaHRc/oNCYJeX7cX4+8O26e/KQa3cQqDJxUG6uwLcdkb/XmpFTI7dX4iUe1DP0rFBF7RkylSLbbhdkp+kUxB8xl6OjQa1u0ZaKTllEwF0CMDrFrQ=";
        pvk = pvk.replace("-----BEGIN PRIVATE KEY-----", "");
        pvk = pvk.replace("-----END PRIVATE KEY-----", "");
        pvk = pvk.replaceAll("\\s+","");
        pvk = pvk.replaceAll("\\n+","");

        String token = generateJwtToken(pvk,"starting-account-1t7zwavrq8v4@aerobic-pivot-231609.iam.gserviceaccount.com","https://www.googleapis.com/oauth2/v4/token","https://www.googleapis.com/auth/dataplansharing",1);
        System.out.println("TOKEN:");
        System.out.println(token);
    }

    private static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
    public static Date addHoursToJavaUtilDate(Date date, int hours) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.HOUR_OF_DAY, hours);
        return calendar.getTime();
    }


    @SuppressWarnings("deprecation")
    public static String generateJwtToken(String Key, String Issuer, String Audience, String Scope, Integer DurationExp) {
        PrivateKey privateKey = getPrivateKey(Key);
        return Jwts.builder()
                .setExpiration(addHoursToJavaUtilDate(new Date(),DurationExp))
                .setIssuer(Issuer)
                .setAudience(Audience)
                .claim("scope", Scope)
                // RS256 with privateKey
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.RS256, privateKey).compact();
    }

}