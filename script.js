/**
 * RSA x 114514 純數字論證器 (長文本支援版)
 * 定製：256-bit 分段加密 + 810 分隔符
 */

const HOMO_MAP = [
    "114514", "1919", "364364", "114", "514", 
    "889464", "364", "931", "893", "1145141919"
];
const SEPARATOR = "810";
const BLOCK_SEPARATOR = "810810810"; // 用三組 810 來分隔不同的加密區塊

/**
 * 數碼編解碼
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEPARATOR);
}

function decodeFromNumbers(str) {
    const parts = str.split(SEPARATOR);
    let resultNum = "";
    parts.forEach(part => {
        const index = HOMO_MAP.indexOf(part);
        if (index !== -1) resultNum += index.toString();
    });
    let chars = [];
    for (let i = 0; i < resultNum.length; i += 3) {
        let code = resultNum.substring(i, i + 3);
        if (code.length === 3) chars.push(String.fromCharCode(parseInt(code)));
    }
    return chars.join('');
}

/**
 *  加密功能 (分段處理)
 */
function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與內容");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);

    // 256-bit RSA 建議每段切 20 個字元以確保 100% 成功
    const CHUNK_SIZE = 20;
    let encryptedBlocks = [];

    for (let i = 0; i < text.length; i += CHUNK_SIZE) {
        const chunk = text.substring(i, i + CHUNK_SIZE);
        const rsaRes = encryptor.encrypt(chunk);
        
        if (!rsaRes) return alert("加密失敗，請檢查金鑰格式。");
        
        // 將這一塊 RSA 密文轉為數字碼
        const homoBlock = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join(SEPARATOR);
        encryptedBlocks.push(homoBlock);
    }

    // 用特殊的塊分隔符連接
    const finalResult = encryptedBlocks.join(BLOCK_SEPARATOR);
    document.getElementById('encryptOutput').innerText = finalResult;
    localStorage.setItem('rsa_pub_cache', key);
}

/**
 *  解密功能 (分段還原)
 */
function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    const decryptor = new JSEncrypt();
    decryptor.setPrivateKey(key);

    try {
        // 先切開大區塊
        const blocks = formula.split(BLOCK_SEPARATOR);
        let finalPlainText = "";

        blocks.forEach(block => {
            const base64 = decodeFromNumbers(block);
            const decryptedChunk = decryptor.decrypt(base64);
            if (decryptedChunk) {
                finalPlainText += decryptedChunk;
            }
        });

        document.getElementById('decryptOutput').innerText = finalPlainText || "解密失敗：金鑰不匹配";
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        alert("數字牆解析失敗，格式可能受損。");
    }
}

/**
 * 金鑰與自動同步功能
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;
    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("✅ 256-bit 金鑰對已生成！"));
    }
}

function copyToDecrypt() {
    document.getElementById('decryptInput').value = document.getElementById('encryptOutput').innerText;
}

window.onload = () => {
    const savedPub = localStorage.getItem('rsa_pub_cache');
    const savedPriv = localStorage.getItem('rsa_priv_cache');
    if (savedPub) document.getElementById('encryptKeyInput').value = savedPub;
    if (savedPriv) document.getElementById('decryptKeyInput').value = savedPriv;
};