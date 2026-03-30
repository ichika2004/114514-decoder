/**
 * RSA x AES 混合論證器 (NSYSU IM 穩定版)
 * 邏輯：RSA 加密 AES 金鑰，AES 加密主體內容，再轉換為純數字牆
 */

// 1. 映射表：不含 0，由 SEP 提供視覺上的 810
const HOMO_MAP = [
    "114514", "1919", "81", "114", "514", 
    "889464", "364", "931", "893", "1145141919"
];

const SEP = "0";     // 數字分隔
const C_SEP = "00";  // 字元分隔
const B_SEP = "000"; // 區塊分隔 (分開 RSA 金鑰區與 AES 資料區)

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/**
 * 編碼：Base64 字串 -> 純數字
 */
function encodeToHomo(b64Str) {
    return b64Str.split('').map(char => {
        const index = B64_CHARS.indexOf(char);
        if (index === -1) return "";
        return index.toString().padStart(2, '0').split('')
            .map(digit => HOMO_MAP[parseInt(digit)])
            .join(SEP);
    }).join(C_SEP);
}

/**
 * 解碼：純數字 -> Base64 字串
 */
function decodeFromHomo(homoStr) {
    const chars = homoStr.split(C_SEP).filter(c => c.length > 0);
    let resB64 = "";
    chars.forEach(charStr => {
        const digits = charStr.split(SEP).filter(d => d.length > 0);
        let indexStr = "";
        digits.forEach(d => {
            const idx = HOMO_MAP.indexOf(d);
            if (idx !== -1) indexStr += idx.toString();
        });
        if (indexStr.length === 2) resB64 += B64_CHARS[parseInt(indexStr)];
    });
    return resB64;
}

/**
 *  加密功能
 */
function doEncrypt() {
    const pubKey = document.getElementById('encryptKeyInput').value.trim();
    const plainText = document.getElementById('encryptInput').value;
    if (!pubKey || !plainText) return alert("請填寫公鑰與內容");

    // 1. 產生 16 位隨機 AES 金鑰
    const aesKey = Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);

    // 2. 用 RSA 加密 AES 金鑰 (這部分長度固定)
    const rsaEncryptor = new JSEncrypt();
    rsaEncryptor.setPublicKey(pubKey);
    const encryptedAesKey = rsaEncryptor.encrypt(aesKey);
    if (!encryptedAesKey) return alert("RSA 加密失敗，請檢查公鑰。");

    // 3. 用 AES 加密內容 (非常短)
    const encryptedContent = CryptoJS.AES.encrypt(plainText, aesKey).toString();

    // 4. 全部轉換為純數字
    const homoKey = encodeToHomo(encryptedAesKey);
    const homoBody = encodeToHomo(encryptedContent);

    // 5. 組合：[RSA 加密後的金鑰] 000 [AES 加密後的內容]
    document.getElementById('encryptOutput').innerText = homoKey + B_SEP + homoBody;
    localStorage.setItem('rsa_pub_cache', pubKey);
}

/**
 *  解密功能
 */
function doDecrypt() {
    const privKey = document.getElementById('decryptKeyInput').value.trim();
    const formula = document.getElementById('decryptInput').value.trim();
    if (!privKey || !formula) return alert("請填寫私鑰與密文");

    try {
        // 1. 分離金鑰區與資料區
        const parts = formula.split(B_SEP);
        if (parts.length < 2) throw new Error("密文格式錯誤");

        // 2. 還原 RSA 部分並取得 AES 金鑰
        const b64Key = decodeFromHomo(parts[0]);
        const rsaDecryptor = new JSEncrypt();
        rsaDecryptor.setPrivateKey(privKey);
        const aesKey = rsaDecryptor.decrypt(b64Key);

        if (!aesKey) return alert("解密失敗：RSA 私鑰不匹配");

        // 3. 還原 AES 部分並取得內容
        const b64Content = decodeFromHomo(parts[1]);
        const bytes = CryptoJS.AES.decrypt(b64Content, aesKey);
        const finalResult = bytes.toString(CryptoJS.enc.Utf8);

        document.getElementById('decryptOutput').innerText = finalResult || "解密失敗：內容損壞";
        localStorage.setItem('rsa_priv_cache', privKey);
    } catch (e) {
        console.error(e);
        alert("還原失敗，請檢查私鑰或密文完整性。");
    }
}

/**
 * 生成金鑰
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;
    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    alert("會員制 256-bit 混合加密金鑰已生成！");
}

function copyToDecrypt() {
    const res = document.getElementById('encryptOutput').innerText;
    if (res.length > 10) document.getElementById('decryptInput').value = res;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub_cache') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv_cache') || "";
};