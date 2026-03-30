/**
 * RSA x 114514 純數字論證器 (穩定分段版)
 * 解決：0/00/000 階梯分隔衝突
 */

// 1. 映射表：必須移除所有內部 0，由分隔符補齊視覺效果
const HOMO_MAP = [
    "114514",       // 0
    "1919",         // 1
    "81",           // 2 (拼上 SEP 後視覺為 810)
    "114",          // 3
    "514",          // 4
    "889464",       // 5 
    "364",          // 6 
    "931",          // 7
    "893",          // 8
    "1145141919"    // 9 
];

const SEP = "0";     // 分隔數字
const C_SEP = "00";  // 分隔字元 (Character)
const B_SEP = "000"; // 分隔區塊 (RSA Block)

/**
 * 編碼：將一個字元轉為數碼序列
 */
function encodeChar(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEP);
}

/**
 * 解碼：從數字牆還原 Base64
 */
function decodeToBase64(blockStr) {
    // 先按字元分隔符 (00) 切開
    const chars = blockStr.split(C_SEP).filter(c => c.length > 0);
    let resultBase64 = "";

    chars.forEach(charStr => {
        // 再按數字分隔符 (0) 切開
        const digits = charStr.split(SEP).filter(d => d.length > 0);
        let charCodeStr = "";
        digits.forEach(d => {
            const idx = HOMO_MAP.indexOf(d);
            if (idx !== -1) charCodeStr += idx.toString();
        });
        if (charCodeStr.length === 3) {
            resultBase64 += String.fromCharCode(parseInt(charCodeStr));
        }
    });
    return resultBase64;
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

    const CHUNK_SIZE = 5; // 256-bit 建議長度
    let encryptedBlocks = [];

    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        const chunk = text.substring(i, i + CHUNK_SIZE);
        const rsaRes = encryptor.encrypt(chunk);
        
        if (!rsaRes) continue;
        
        // 轉換為數字串：字元之間用 00 隔開
        const homoBlock = rsaRes.split('').map(c => encodeChar(c.charCodeAt(0))).join(C_SEP);
        encryptedBlocks.push(homoBlock);
    }

    // 區塊之間用 000 隔開
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
        // 依據區塊分隔符 (000) 切開
        const blocks = formula.split(B_SEP).filter(b => b.length > 10);
        let finalResult = "";

        blocks.forEach((block, idx) => {
            const base64 = decodeToBase64(block);
            const decrypted = decryptor.decrypt(base64);
            if (decrypted) {
                finalResult += decrypted;
            } else {
                console.error(`第 ${idx + 1} 區塊 RSA 解密失敗。還原 Base64: ${base64}`);
            }
        });

        document.getElementById('decryptOutput').innerText = finalResult || "解密失敗：內容損壞或金鑰不符";
    } catch (e) {
        console.error(e);
        alert("解析失敗，請確認密文完整性。");
    }
}

/**
 * 金鑰與輔助
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;
    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    alert(" 256-bit PEM 金鑰已生成！");
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    document.getElementById('encryptKeyInput').value = localStorage.getItem('rsa_pub_cache') || "";
    document.getElementById('decryptKeyInput').value = localStorage.getItem('rsa_priv_cache') || "";
};