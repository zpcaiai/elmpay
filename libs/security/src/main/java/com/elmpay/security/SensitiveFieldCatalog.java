// GENERATED FILE — scripts/render-paymethod.py; do not edit by hand
// Source of truth: governance/payment-method.json
package com.elmpay.security;

import java.util.Set;

/**
 * Field names that must never reach storage, logs, traces or CI artefacts.
 *
 * <p>Names are normalised before comparison — lower-cased with {@code _ - .} and spaces
 * removed — so {@code card_pan}, {@code cardPan} and {@code CARD-PAN} are one name, not three.
 * Before B35 they were three, which is how {@code card_pan} passed a guard that was watching
 * {@code pan}.
 *
 * <ul>
 *   <li>credential — 凭证不进日志、不进数据库明文、不进异常与追踪。裸的 `private` 也在内：收银台的参数正则一直拦着它，而本目录一开始漏了，这正是本批次要消灭的那种「每一层各有一份、互相漏掉对方」。</li>
 *   <li>cvv — 验证码在授权后禁止留存，任何形式、任何时长。</li>
 *   <li>pan — 主账号本身。任何长度 13–19 的连续数字串也按此处理。</li>
 *   <li>pin — PIN 及其密文块。</li>
 *   <li>track_data — 磁道数据包含 PAN 与服务码，等价于卡的完整复制品。</li>
 *   <li>wallet_cleartext — 解密后的钱包支付数据是一次性可用的支付凭证，落盘即等于把一次扣款权限存了下来。</li>
 * </ul>
 */
public final class SensitiveFieldCatalog {
    /** Normalised names. Compare with {@link #normalize(String)}, never raw. */
    public static final Set<String> DENIED_KEYS = Set.of(
            "accountnumber", "apikey", "applepaytoken", "authorization", "authorizationheader",
            "cardcvv", "cardno", "cardnumber", "cardpan", "cardpin", "cardverificationvalue",
            "cav2", "cid", "clientsecret", "credential", "cryptogram", "csc", "cvc", "cvc2", "cvv",
            "cvv2", "decryptedtoken", "dpan", "fpan", "magneticstripe", "magstripe",
            "onlinepaymentcryptogram", "pan", "password", "paymentdata", "paymenttokencleartext",
            "pin", "pinblock", "pindata", "primaryaccountnumber", "private", "privatekey",
            "secret", "securitycode", "track1", "track2", "track3", "trackdata", "walletcleartext");

    /** Schemes a payment-method reference may use. An allowlist, deliberately. */
    public static final Set<String> TOKEN_SCHEMES = Set.of(
            "mandate", "psp", "wallet");

    /** Fields that may be shown to a human or returned by an API. */
    public static final Set<String> DISPLAY_ALLOWLIST = Set.of(
            "brand", "expiry_month", "expiry_year", "last4", "method", "provider");

    private SensitiveFieldCatalog() {
    }

    /** Lower-case and drop separators, so one field name is one name. */
    public static String normalize(String name) {
        if (name == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder(name.length());
        for (int index = 0; index < name.length(); index++) {
            char character = name.charAt(index);
            if (character == '_' || character == '-' || character == '.' || character == ' ') {
                continue;
            }
            builder.append(Character.toLowerCase(character));
        }
        return builder.toString();
    }

    /** True when the name is forbidden under any spelling. */
    public static boolean denied(String name) {
        return DENIED_KEYS.contains(normalize(name));
    }
}
