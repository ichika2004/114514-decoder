/**
 * RSA x 114514 純數字論證器 (NSYSU IM 專業版)
 * 定製：使用 810 作為分隔符，套用使用者指定 HOMO_MAP
 */

// 1. 完全遵循使用者指定的數碼映射
const HOMO_MAP = [
    "114514",       // 0
    "1919",         // 1
    "364364",       // 2 
    "114",          // 3
    "514",          // 4
    "889464",       // 5 
    "364",          // 6 
    "931",          // 7
    "893",          // 8
    "1145141919"    // 9 
];

const SEPARATOR = "810";

/**
 * 編碼邏輯：ASCII(065) -> "114514810811919810191981"
 */
function encodeToNumbers(code) {
    return code.toString().padStart(3, '0').split('')
        .map(digit => HOMO_MAP[parseInt(digit)])
        .join(SEPARATOR);
}

/**
 * 解碼邏輯：利用 810 分隔符精確切割
 */
function decodeFromNumbers(str) {
    if (!str) return "";
    // 先按 810 切開，保證 364364 不會被誤認成兩個 364
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
 * 🚀 金鑰生成 (256-bit PEM)
 */
function generateTestKeys() {
    const crypt = new JSEncrypt({ default_key_size: 256 });
    alert("正在生成 256-bit PEM 金鑰...");
    const pub = crypt.getPublicKey();
    const priv = crypt.getPrivateKey();
    
    document.getElementById('encryptKeyInput').value = pub;
    document.getElementById('decryptKeyInput').value = priv;

    localStorage.setItem('rsa_pub_cache', pub);
    localStorage.setItem('rsa_priv_cache', priv);
    
    if (navigator.clipboard) {
        navigator.clipboard.writeText(priv).then(() => alert("✅ 金鑰已填入，私鑰已複製！"));
    }
}

function doEncrypt() {
    const key = document.getElementById('encryptKeyInput').value;
    const text = document.getElementById('encryptInput').value;
    if (!key || !text) return alert("請輸入公鑰與明文");

    const encryptor = new JSEncrypt();
    encryptor.setPublicKey(key);
    const rsaRes = encryptor.encrypt(text);

    if (!rsaRes) return alert("加密失敗！256-bit 限制長度約 20 字。");

    // 每一組字元編碼之間也用 810 連結，形成壯觀的數字牆
    const result = rsaRes.split('').map(c => encodeToNumbers(c.charCodeAt(0))).join(SEPARATOR);
    document.getElementById('encryptOutput').innerText = result;
    localStorage.setItem('rsa_pub_cache', key);
}

function doDecrypt() {
    const key = document.getElementById('decryptKeyInput').value;
    const formula = document.getElementById('decryptInput').value.trim();
    if (!key || !formula) return alert("請輸入私鑰與密文");

    try {
        const base64 = decodeFromNumbers(formula);
        const decryptor = new JSEncrypt();
        decryptor.setPrivateKey(key);
        const final = decryptor.decrypt(base64);
        
        document.getElementById('decryptOutput').innerText = final || "解密失敗：金鑰不匹配";
        localStorage.setItem('rsa_priv_cache', key);
    } catch (e) {
        alert("數字牆解析失敗。");
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