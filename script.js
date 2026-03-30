/**
 * RSA x 114514 純數字論證器 (高密度優化版)
 * 特色：6-bit 直接映射技術，密文長度縮減 33%
 */

// 1. 映射表：維持不含 0 的原則
const HOMO_MAP = ["114514", "1919", "81", "114", "514", "889464", "364", "931", "893", "1145141919"];
const SEP = "0";     // 分隔數字
const C_SEP = "00";  // 分隔 Base64 字元
const B_SEP = "000"; // 分隔 RSA 區塊

// Base64 索引表
const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

/**
 * 高密度編碼：將 1 個 Base64 字元轉為 2 組數碼 (00~64)
 */
function encodeB64Char(char) {
    const index = B64_CHARS.indexOf(char);
    if (index === -1) return "";
    // 將索引轉為 2 位數 (00-64)，例如 index 5 變成 "05"
    return index.toString().padStart(2, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEP);
}

/**
 * 高密度解碼：從數碼牆還原 Base64
 */
function decodeToB64(blockStr) {
    const chars = blockStr.split(C_SEP).filter(c => c.length > 0);
    let resultB64 = "";

    chars.forEach(charStr => {
        const digits = charStr.split(SEP).filter(d => d.length > 0);
        let indexStr = "";
        digits.forEach(d => {
            const idx = HOMO_MAP.indexOf(d);
            if (idx !== -1) indexStr += idx.toString();
        });
        if (indexStr.length === 2) {
            resultB64 += B64_CHARS[parseInt(indexStr)];
        }
    });
    return resultB64;
}

/**
 *  加密功能
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value.trim();
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與內容");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);

    const CHUNK_SIZE = 10; // 密度提高後，分段可以稍微放大
    let encryptedBlocks = [];

    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        const chunk = text.substring(i, i + CHUNK_SIZE);
        const rsaRes = encryptor.encrypt(chunk);
        if (!rsaRes) continue;
        
        // 直接對 RSA 產出的 Base64 字串進行高密度映射
        const homoBlock = rsaRes.split('').map(c => encodeB64Char(c)).join(C_SEP);
        encryptedBlocks.push(homoBlock);
    }
    document.getElementById('encryptOutput').innerText = encryptedBlocks.join(B_SEP);
}

/**
 *  解密功能
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
            const base64 = decodeToB64(block);
            const decrypted = decryptor.decrypt(base64);
            if (decrypted) {
                finalResult += decrypted;
            } else {
                console.error(`第 ${idx + 1} 區塊解密失敗`);
            }
        });
        document.getElementById('decryptOutput').innerText = finalResult || "解密失敗：金鑰不符";
    } catch (e) {
        alert("數字牆損壞，無法解析。");
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
    alert(" 會員制 256-bit 金鑰對已生成！");
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub_cache') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv_cache') || "";
};