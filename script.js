/**
 * RSA x 114514 純數字論證器 (高密度穩定版)
 * 解決：利用 0, 2, 7 進行三級隔離，徹底消除解析歧義
 */

// 映射表：確保不含分隔符號 0, 2, 7
const HOMO_MAP = [
    "114514",       // 0
    "1919",         // 1
    "81",           // 2 (與 SEP 拼接後視覺依然含有 8, 1)
    "114",          // 3
    "514",          // 4
    "889464",       // 5 
    "364",          // 6 
    "931",          // 7 -> 注意：如果字典有 931，則 7 不能當分隔符。
    "893",          // 8
    "1145141919"    // 9 
];

// 重新校對：字典裡含有 1, 3, 4, 5, 6, 8, 9。 
// 真正完全沒出現的數字是：0, 2, 7 (但 7 在 931 裡出現過)。
// 所以我們改用：0, 2 作為分隔符。

const SEP = "0";     // 一級：分隔數碼 (例如 00)
const C_SEP = "020"; // 二級：分隔字元 (例如 A 與 B)
const B_SEP = "222"; // 三級：分隔區塊 (RSA 區塊)

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/**
 * 編碼：Base64 字元 -> 純數字
 */
function encodeB64Char(char) {
    const index = B64_CHARS.indexOf(char);
    if (index === -1) return "";
    return index.toString().padStart(2, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEP);
}

/**
 * 解碼：純數字 -> Base64 字元
 */
function decodeFromHomo(blockStr) {
    const chars = blockStr.split(C_SEP).filter(c => c.length > 0);
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
 *  加密 (分段控制)
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value.trim();
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與內容");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);

    // 256-bit 安全分段：每段 4 個字元 (絕對不溢位)
    const CHUNK_SIZE = 4;
    let encryptedBlocks = [];

    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        const chunk = text.substring(i, i + CHUNK_SIZE);
        const rsaRes = encryptor.encrypt(chunk);
        if (!rsaRes) continue;
        
        const homoBlock = rsaRes.split('').map(c => encodeB64Char(c)).join(C_SEP);
        encryptedBlocks.push(homoBlock);
    }
    document.getElementById('encryptOutput').innerText = encryptedBlocks.join(B_SEP);
}

/**
 *  解密 (穩定還原)
 */
function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value.trim();
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(key);

    try {
        const blocks = formula.split(B_SEP).filter(b => b.length > 10);
        let finalResult = "";

        blocks.forEach((block, idx) => {
            const b64 = decodeFromHomo(block);
            const decrypted = decryptor.decrypt(b64);
            if (decrypted) {
                finalResult += decrypted;
            } else {
                console.error(`第 ${idx + 1} 區塊 RSA 解密失敗，還原 B64 為: ${b64}`);
            }
        });
        document.getElementById('decryptOutput').innerText = finalResult || "解密失敗：金鑰不匹配";
    } catch (e) {
        alert("數字牆格式損壞，無法解析。");
    }
}

/**
 * 金鑰與自動同步
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;
    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    alert("特製 256-bit 金鑰對已生成！");
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub_cache') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv_cache') || "";
};